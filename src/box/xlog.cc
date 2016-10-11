/*
 * Copyright 2010-2016, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "xlog.h"
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>

#include "fiber.h"
#include "crc32.h"
#include "fio.h"
#include "fiob.h"
#include "third_party/tarantool_eio.h"
#include <msgpuck.h>
#include "scoped_guard.h"

#include "error.h"
#include "xrow.h"
#include "iproto_constants.h"
#include "errinj.h"

/*
 * marker is MsgPack fixext2
 * +--------+--------+--------+--------+
 * |  0xd5  |  type  |       data      |
 * +--------+--------+--------+--------+
 */
typedef uint32_t log_magic_t;

static const log_magic_t row_marker = mp_bswap_u32(0xd5ba0bab); /* host byte order */
static const log_magic_t zrow_marker = mp_bswap_u32(0xd5ba0bba); /* host byte order */
static const log_magic_t eof_marker = mp_bswap_u32(0xd510aded); /* host byte order */
static const char inprogress_suffix[] = ".inprogress";
static const char v13[] = "0.13\n";
static const char v12[] = "0.12\n";

enum {
	/**
	 * When the number of rows in xlog_tx write buffer
	 * gets this big, don't delay flush any longer, and
	 * issue a write.
	 * This also acts as a default for slab size in the
	 * slab cache so must be a power of 2.
	 */
	XLOG_TX_AUTOCOMMIT_THRESHOLD = 128 * 1024,
	/**
	 * Compress output buffer before dumping it to
	 * disk if it is at least this big. On smaller
	 * sizes compression takes up CPU but doesn't
	 * yield seizable gains.
	 * Maybe this should be a configuration option.
	 */
	XLOG_TX_COMPRESS_THRESHOLD = 2 * 1024,
};

const struct type type_XlogError = make_type("XlogError", &type_Exception);
XlogError::XlogError(const char *file, unsigned line,
		     const char *format, ...)
	:Exception(&type_XlogError, file, line)
{
	va_list ap;
	va_start(ap, format);
	error_vformat_msg(this, format, ap);
	va_end(ap);
}

XlogError::XlogError(const struct type *type, const char *file, unsigned line,
		     const char *format, ...)
	:Exception(type, file, line)
{
	va_list ap;
	va_start(ap, format);
	error_vformat_msg(this, format, ap);
	va_end(ap);
}

const struct type type_XlogGapError =
	make_type("XlogGapError", &type_XlogError);

XlogGapError::XlogGapError(const char *file, unsigned line,
			   const struct vclock *from,
			   const struct vclock *to)
	:XlogError(&type_XlogGapError, file, line, "")
{
	char *s_from = vclock_to_string(from);
	char *s_to = vclock_to_string(to);
	snprintf(errmsg, sizeof(errmsg),
		 "Missing .xlog file between LSN %lld %s and %lld %s",
		 (long long) vclock_sum(from), s_from ? s_from : "",
		 (long long) vclock_sum(to), s_to ? s_to : "");
	free(s_from);
	free(s_to);
}

/* {{{ struct xdir */

void
xdir_create(struct xdir *dir, const char *dirname,
	    enum xdir_type type, const tt_uuid *server_uuid)
{
	memset(dir, 0, sizeof(*dir));
	vclockset_new(&dir->index);
	/* Default mode. */
	dir->mode = 0660;
	dir->server_uuid = server_uuid;
	snprintf(dir->dirname, PATH_MAX, "%s", dirname);
	if (type == SNAP) {
		strcpy(dir->open_wflags, "cwrxd");
		dir->filetype = "SNAP\n";
		dir->filename_ext = ".snap";
		dir->panic_if_error = true;
		dir->suffix = INPROGRESS;
	} else {
		strcpy(dir->open_wflags, "cwrx");
		dir->sync_is_async = true;
		dir->filetype = "XLOG\n";
		dir->filename_ext = ".xlog";
		dir->suffix = NONE;
	}
	dir->type = type;
}

/**
 * Delete all members from the set of vector clocks.
 */
static void
vclockset_reset(vclockset_t *set)
{
	struct vclock *vclock = vclockset_first(set);
	while (vclock != NULL) {
		struct vclock *next = vclockset_next(set, vclock);
		vclockset_remove(set, vclock);
		free(vclock);
		vclock = next;
	}
}

/**
 * Destroy xdir object and free memory.
 */
void
xdir_destroy(struct xdir *dir)
{
	/** Free vclock objects allocated in xdir_scan(). */
	vclockset_reset(&dir->index);
}

/**
 * Add a single log file to the index of all log files
 * in a given log directory.
 */
static inline int
xdir_index_file(struct xdir *dir, int64_t signature)
{
	/*
	 * Open xlog and parse vclock in its text header.
	 * The vclock stores the state of the log at the
	 * time it is created.
	 */
	struct xlog *wal = xlog_open(dir, signature);
	if (wal == NULL)
		return -1;

	/*
	 * All log files in a directory must satisfy Lamport's
	 * eventual order: events in each log file must be
	 * separable with consistent cuts, for example:
	 *
	 * log1: {1, 1, 0, 1}, log2: {1, 2, 0, 2} -- good
	 * log2: {1, 1, 0, 1}, log2: {2, 0, 2, 0} -- bad
	 */
	struct vclock *dup = vclockset_search(&dir->index, &wal->vclock);
	if (dup != NULL) {
		tnt_error(XlogError, "%s: invalid xlog order", wal->filename);
		xlog_close(wal);
		return -1;
	}

	/*
	 * Append the clock describing the file to the
	 * directory index.
	 */
	struct vclock *vclock = (struct vclock *) malloc(sizeof(*vclock));
	if (vclock == NULL) {
		tnt_error(OutOfMemory, sizeof(*vclock), "malloc", "vclock");
		xlog_close(wal);
		return -1;
	}

	vclock_copy(vclock, &wal->vclock);
	xlog_close(wal);
	vclockset_insert(&dir->index, vclock);
	return 0;
}

static int
cmp_i64(const void *_a, const void *_b)
{
	const int64_t *a = (const int64_t *) _a, *b = (const int64_t *) _b;
	if (*a == *b)
		return 0;
	return (*a > *b) ? 1 : -1;
}

/**
 * Scan (or rescan) a directory with snapshot or write ahead logs.
 * Read all files matching a pattern from the directory -
 * the filename pattern is \d+.xlog
 * The name of the file is based on its vclock signature,
 * which is the sum of all elements in the vector clock recorded
 * when the file was created. Elements in the vector
 * reflect log sequence numbers of servers in the asynchronous
 * replication set (see also _cluster system space and vclock.h
 * comments).
 *
 * This function tries to avoid re-reading a file if
 * it is already in the set of files "known" to the log
 * dir object. This is done to speed up local hot standby and
 * recovery_follow_local(), which periodically rescan the
 * directory to discover newly created logs.
 *
 * On error, this function throws an exception. If
 * dir->panic_if_error is false, *some* errors are not
 * propagated up but only logged in the error log file.
 *
 * The list of errors ignored in panic_if_error = false mode
 * includes:
 * - a file can not be opened
 * - some of the files have incorrect metadata (such files are
 *   skipped)
 *
 * The goal of panic_if_error = false mode is partial recovery
 * from a damaged/incorrect data directory. It doesn't
 * silence conditions such as out of memory or lack of OS
 * resources.
 *
 * @return nothing.
 */
int
xdir_scan(struct xdir *dir)
{
	DIR *dh = opendir(dir->dirname);        /* log dir */
	int64_t *signatures = NULL;             /* log file names */
	size_t s_count = 0, s_capacity = 0;

	if (dh == NULL) {
		tnt_error(SystemError, "error reading directory '%s'",
			  dir->dirname);
		return -1;
	}

	auto dir_guard = make_scoped_guard([&]{
		closedir(dh);
		free(signatures);
	});

	struct dirent *dent;
	/*
	  A note regarding thread safety, readdir vs. readdir_r:

	  POSIX explicitly makes the following guarantee: "The
	  pointer returned by readdir() points to data which may
	  be overwritten by another call to readdir() on the same
	  directory stream. This data is not overwritten by another
	  call to readdir() on a different directory stream.

	  In practice, you don't have a problem with readdir(3)
	  because Android's bionic, Linux's glibc, and OS X and iOS'
	  libc all allocate per-DIR* buffers, and return pointers
	  into those; in Android's case, that buffer is currently about
	  8KiB. If future file systems mean that this becomes an actual
	  limitation, we can fix the C library and all your applications
	  will keep working.

	  See also
	  http://elliotth.blogspot.co.uk/2012/10/how-not-to-use-readdirr3.html
	*/
	while ((dent = readdir(dh)) != NULL) {
		char *ext = strchr(dent->d_name, '.');
		if (ext == NULL)
			continue;
		/*
		 * Compare the rest of the filename with
		 * dir->filename_ext.
		 */
		if (strcmp(ext, dir->filename_ext) != 0)
			continue;

		char *dot;
		long long signature = strtoll(dent->d_name, &dot, 10);
		if (ext != dot ||
		    signature == LLONG_MAX || signature == LLONG_MIN) {
			say_warn("can't parse `%s', skipping", dent->d_name);
			continue;
		}

		if (s_count == s_capacity) {
			s_capacity = s_capacity > 0 ? 2 * s_capacity : 16;
			size_t size = sizeof(*signatures) * s_capacity;
			signatures = (int64_t *) realloc(signatures, size);
			if (signatures == NULL) {
				tnt_error(OutOfMemory,
					  size, "realloc", "signatures array");
				return -1;
			}
		}
		signatures[s_count++] = signature;
	}
	/** Sort the list of files */
	qsort(signatures, s_count, sizeof(*signatures), cmp_i64);
	/**
	 * Update the log dir index with the current state:
	 * remove files which no longer exist, add files which
	 * appeared since the last scan.
	 */
	struct vclock *vclock = vclockset_first(&dir->index);
	unsigned i = 0;
	while (i < s_count || vclock != NULL) {
		int64_t s_old = vclock ? vclock_sum(vclock) : LLONG_MAX;
		int64_t s_new = i < s_count ? signatures[i] : LLONG_MAX;
		if (s_old < s_new) {
			/** Remove a deleted file from the index */
			struct vclock *next =
				vclockset_next(&dir->index, vclock);
			vclockset_remove(&dir->index, vclock);
			free(vclock);
			vclock = next;
		} else if (s_old > s_new) {
			/** Add a new file. */
			if (xdir_index_file(dir, s_new) != 0) {
				/*
				 * panic_if_error must not affect OOM
				 */
				struct error *e = diag_last_error(&fiber()->diag);
				if (dir->panic_if_error ||
				    type_cast(OutOfMemory, e))
					return -1;
				/** Skip a corrupted file */
				error_log(e);
				return 0;
			}
			i++;
		} else {
			assert(s_old == s_new && i < s_count &&
			       vclock != NULL);
			vclock = vclockset_next(&dir->index, vclock);
			i++;
		}
	}
	return 0;
}

int
xdir_check(struct xdir *dir)
{
	DIR *dh = opendir(dir->dirname);        /* log dir */
	if (dh == NULL) {
		tnt_error(SystemError, "error reading directory '%s'",
			  dir->dirname);
		return -1;
	}
	closedir(dh);
	return 0;
}

char *
format_filename(struct xdir *dir, int64_t signature,
		enum log_suffix suffix)
{
	static __thread char filename[PATH_MAX + 1];
	const char *suffix_str = (suffix == INPROGRESS ?
				  inprogress_suffix : "");
	snprintf(filename, PATH_MAX, "%s/%020lld%s%s",
		 dir->dirname, (long long) signature,
		 dir->filename_ext, suffix_str);
	return filename;
}

/* }}} */

/* {{{ struct xlog_cursor */

/**
 * Decompress zstd-compressed buf into cursor data block
 */
static int
xlog_cursor_decompress(struct xlog_cursor *i)
{
	if (!ibuf_capacity(&i->zbuf)) {
		/* Preallocate some space for zstd output buffer */
		if (!ibuf_reserve(&i->zbuf,
				  2 * XLOG_TX_AUTOCOMMIT_THRESHOLD)) {
			tnt_error(OutOfMemory,
				  XLOG_TX_AUTOCOMMIT_THRESHOLD,
				  "slab", "xlog decompression buffer");
			return -1;
		}
	} else {
		ibuf_reset(&i->zbuf);
	}

	ZSTD_initDStream(i->zdctx);
	ZSTD_inBuffer input = {i->rpos, (size_t)(i->epos - i->rpos), 0};
	while (input.pos < input.size) {
		/* Process zstd stream to decompress */
		ZSTD_outBuffer output = {i->zbuf.wpos,
					 ibuf_unused(&i->zbuf),
					 0};
		size_t rc = ZSTD_decompressStream(i->zdctx,
						  &output,
						  &input);
		ibuf_alloc(&i->zbuf, output.pos);
		if (rc >= 1) {
			/* Not enougth space for decompressed output */
			if (!ibuf_reserve(&i->zbuf,
					  ibuf_capacity(&i->zbuf))){
				tnt_error(OutOfMemory,
					  2 * ibuf_capacity(&i->zbuf),
					  "runtime arena",
					  "xlog decompression buffer");
				return -1;
			}
			continue;
		}
		if (rc == 0) {
			/* Decompression done */
			break;
		}
		if (ZSTD_isError(rc)) {
			tnt_error(ClientError, ER_COMPRESSION, rc);
			return -1;
		}
	}
	/* Set row buffer */
	i->rpos = i->zbuf.rpos;
	i->epos = i->zbuf.wpos;
	return 0;
}

/**
 * @retval -1 error
 * @retval 0 success
 * @retval 1 EOF
 */
static int
xlog_cursor_read_tx(struct xlog_cursor *i, log_magic_t magic)
{
	/* Read xlog tx from afio reader */
	struct afio *f = i->log->f;
	const char *data;
	uint32_t crc32p, crc32c, len;

	/* Read fixed header (without magic) */
	ssize_t to_read = XLOG_FIXHEADER_SIZE - sizeof(log_magic_t);
	char *header;
	ssize_t readen = afio_reader_load(&i->reader,
					  (void **)&header, to_read);
	if (readen < to_read) {
		return 1;
	}

	/* Decode len, previous crc32 and row crc32 */
	data = header;
	if (mp_check(&data, data + readen) != 0)
		goto error;
	data = header;

	/* Read length */
	if (mp_typeof(*data) != MP_UINT)
		goto error;
	len = mp_decode_uint(&data);
	if (len > IPROTO_BODY_LEN_MAX) {
		goto error;
	}

	/* Read previous crc32 */
	if (mp_typeof(*data) != MP_UINT)
		goto error;

	/* Read current crc32 */
	crc32p = mp_decode_uint(&data);
	if (mp_typeof(*data) != MP_UINT)
		goto error;
	crc32c = mp_decode_uint(&data);
	assert(data <= header + to_read);
	(void) crc32p;

	/* Read xlog tx data to reader internal buf */
	if (afio_reader_load(&i->reader, (void **)&i->rpos, len) < len)
		return 1;
	i->epos = i->rpos + len;

	/* Validate checksum */
	if (crc32_calc(0, i->rpos, len) != crc32c) {
		char buf[PATH_MAX];
		snprintf(buf, sizeof(buf), "%s: row block checksum"
			 " mismatch (expected %u) at offset %" PRIu64,
			 afio_name(f), (unsigned) crc32c,
			 (uint64_t)i->reader.rpos - len);
		tnt_error(ClientError, ER_INVALID_MSGPACK, buf);
		return -1;
	}

	if (magic == row_marker) {
		/* Plain row block, just return */
		return 0;
	}

	if (magic == zrow_marker) {
		/* Decompress data */
		return xlog_cursor_decompress(i);
	}

error:
	char buf[PATH_MAX];
	snprintf(buf, sizeof(buf), "%s: failed to parse xlog tx "
		 "header at offset %" PRIu64, afio_name(f),
		 (uint64_t)i->reader.rpos);
	tnt_error(ClientError, ER_INVALID_MSGPACK, buf);
	return -1;
}

static int
xlog_tx_create(struct xlog_tx *block)
{
	/* Create xlog tx and preallocate space in tx tx row buffer */
	block->is_autocommit = true;
	obuf_create(&block->obuf, &cord()->slabc, XLOG_TX_AUTOCOMMIT_THRESHOLD);
	block->zctx = ZSTD_createCCtx();
	if (!block->zctx)
		return -1;
	return 0;
}

static void
xlog_tx_destroy(struct xlog_tx *block)
{
	obuf_destroy(&block->obuf);
	if (block->zctx)
		ZSTD_freeCCtx(block->zctx);
}

/**
 * Write a block of uncompressed xrow objects.
 *
 * @retval -1 error
 * @retval >= 0 the number of bytes written
 */
static off_t
xlog_tx_write_plain(struct xlog *log)
{
	struct xlog_tx *block = &log->xlog_tx;
	/**
	 * We created an obuf savepoint at start of xlog_tx,
	 * now populate it with data.
	 */
	char *fixheader = (char *)block->obuf.iov[0].iov_base;
	*(log_magic_t *)fixheader = row_marker;
	char *data = fixheader + sizeof(log_magic_t);

	data = mp_encode_uint(data,
			      obuf_size(&block->obuf) - XLOG_FIXHEADER_SIZE);
	/* Encode crc32 for previous row */
	data = mp_encode_uint(data, 0);
	/* Encode crc32 for current row */
	uint32_t crc32c = 0;
	struct iovec *iov;
	size_t offset = XLOG_FIXHEADER_SIZE;
	for (iov = block->obuf.iov; iov->iov_len; ++iov) {
		crc32c = crc32_calc(crc32c,
				    (char *)iov->iov_base + offset,
				    iov->iov_len - offset);
		offset = 0;
	}
	data = mp_encode_uint(data, crc32c);
	/*
	 * Encode a padding, to ensure the resulting
	 * fixheader always has the same size.
	 */
	ssize_t padding = XLOG_FIXHEADER_SIZE - (data - fixheader);
	if (padding > 0)
		data = mp_encode_strl(data, padding - 1) + padding - 1;

	/* Write rows to afio appender */
	for (iov = block->obuf.iov; iov->iov_len; ++iov) {
		if (afio_appender_write(&log->appender, iov->iov_base,
					iov->iov_len) < (ssize_t)iov->iov_len) {
			/* Discard output */
			afio_appender_reset(&log->appender);
			return -1;
		}
	}
	/* Flush output to backing store */
	if (afio_appender_flush(&log->appender) <
	    (ssize_t)obuf_size(&block->obuf)) {
		afio_appender_reset(&log->appender);
		return -1;
	}
	return obuf_size(&block->obuf);
}

/**
 * Write a compressed block of xrow objects.
 * @retval -1  error
 * @retval >= 0 the number of bytes written
 */
static off_t
xlog_tx_write_zstd(struct xlog *log)
{
	struct xlog_tx *block = &log->xlog_tx;
	char *fixheader = (char *)afio_appender_alloc(&log->appender,
						      XLOG_FIXHEADER_SIZE);

	uint32_t crc32c = 0;
	size_t zlen = XLOG_FIXHEADER_SIZE;
	struct iovec *iov;
	/* 3 is compression level. */
	ZSTD_compressBegin(block->zctx, 3);
	size_t offset = XLOG_FIXHEADER_SIZE;
	for (iov = block->obuf.iov; iov->iov_len; ++iov) {
		/* Estimate max output buffer size. */
		size_t zmax_size = ZSTD_compressBound(iov->iov_len - offset);
		/* Allocate a destination buffer. */
		void *zdst = afio_appender_reserve(&log->appender, zmax_size);
		if (!zdst) {
			tnt_error(OutOfMemory, zmax_size, "runtime arena",
				  "decompression buffer");
			goto error;
		}
		size_t (*fcompress)(ZSTD_CCtx *, void *, size_t,
				    const void *, size_t);
		/*
		 * If it's the last iov or the last
		 * block has 0 bytes, end the stream.
		 */
		if (iov == block->obuf.iov + block->obuf.pos ||
		    !(iov + 1)->iov_len) {
			fcompress = ZSTD_compressEnd;
		} else {
			fcompress = ZSTD_compressContinue;
		}
		size_t zsize = fcompress(block->zctx, zdst, zmax_size,
					 (char *)iov->iov_base + offset,
					 iov->iov_len - offset);
		if (ZSTD_isError(zsize))
			goto error;
		/* Advance output buffer to the end of compressed data. */
		afio_appender_alloc(&log->appender, zsize);
		zlen += zsize;
		/* Update crc32c */
		crc32c = crc32_calc(crc32c, (char *)zdst, zsize);
		/* Discount fixheader size for all iovs after first. */
		offset = 0;
	}

	*(log_magic_t *)fixheader = zrow_marker;
	char *data;
	data = fixheader + sizeof(log_magic_t);
	data = mp_encode_uint(data, zlen - XLOG_FIXHEADER_SIZE);
	/* Encode crc32 for previous row */
	data = mp_encode_uint(data, 0);
	/* Encode crc32 for current row */
	data = mp_encode_uint(data, crc32c);
	/* Encode padding */
	ssize_t padding;
	padding = XLOG_FIXHEADER_SIZE - (data - fixheader);
	if (padding > 0)
		data = mp_encode_strl(data, padding - 1) + padding - 1;

	ERROR_INJECT(ERRINJ_WAL_WRITE_DISK, {
		afio_appender_reset(&log->appender);
	});

	/* Flush output to backing store */
	if (afio_appender_flush(&log->appender) < (ssize_t)zlen)
		goto error;

	return zlen;
error:
	afio_appender_reset(&log->appender);
	return -1;
}

/**
 * Writes xlog batch to file
 */
static ssize_t
xlog_tx_write(struct xlog *log)
{
	struct xlog_tx *block = &log->xlog_tx;
	if (obuf_size(&block->obuf) == XLOG_FIXHEADER_SIZE)
		return 0;
	ssize_t written;

	if (obuf_size(&block->obuf) >= XLOG_TX_COMPRESS_THRESHOLD) {
		written = xlog_tx_write_zstd(log);
	} else {
		written = xlog_tx_write_plain(log);
	}
	ERROR_INJECT(ERRINJ_WAL_WRITE, written = -1;);

	obuf_reset(&block->obuf);
	block->offset += written > 0 ? written : 0;
	/*
	 * Simplify recovery after a temporary write failure:
	 * truncate the file to the best known good write
	 * position.
	 */
	if (written < 0 &&
	    afio_appender_ftruncate(&log->appender, block->offset) != 0) {
		panic_syserror("failed to truncate xlog");
	}
	return written;
}

/**
 * Flush any outstanding xlog_tx transactions at the end of
 * a WAL write batch.
 */
ssize_t
xlog_flush(struct xlog *log)
{
	assert(log->xlog_tx.is_autocommit);
	return xlog_tx_write(log);
}

/**
 * Begin a multi-statement xlog transaction. All xrow objects
 * of a single transaction share the same header and checksum
 * and are normally written at once.
 */
void
xlog_tx_begin(struct xlog *log)
{
	log->xlog_tx.is_autocommit = false;
}

/*
 * End a non-interruptible batch of rows, thus enable flushes of
 * a transaction at any time, on threshold. If the buffer is big
 * enough already, flush it at once here.
 *
 * @retval -1  error
 * @retval >= 0 the number of bytes written to disk
 */
ssize_t
xlog_tx_commit(struct xlog *log)
{
	log->xlog_tx.is_autocommit = true;
	if (obuf_size(&log->xlog_tx.obuf) >= XLOG_TX_AUTOCOMMIT_THRESHOLD) {
		return xlog_tx_write(log);
	}
	return 0;
}

/*
 * Rollback a batch of buffered rows without writing to file
 */
void
xlog_tx_rollback(struct xlog *log)
{
	log->xlog_tx.is_autocommit = true;
	obuf_reset(&log->xlog_tx.obuf);
}

/*
 * Add a row to a block and possibly flush the block.
 *
 * @retval -1 error
 * @retval >=0 number of bytes flushed to disk by this write.
 */
ssize_t
xlog_write_row(struct xlog *log, const struct xrow_header *packet)
{
	struct xlog_tx *block = &log->xlog_tx;
	/*
	 * Automatically reserve space for a fixheader when adding
	 * the first row in * a block. The fixheader is populated
	 * at write. @sa xlog_tx_write().
	 */
	if (obuf_size(&block->obuf) == 0) {
		if (!obuf_alloc(&block->obuf, XLOG_FIXHEADER_SIZE)) {
			tnt_error(OutOfMemory, XLOG_FIXHEADER_SIZE,
				  "runtime arena", "xlog tx output buffer");
			return -1;
		}
	}

	/** encode row into iovec */
	struct iovec iov[XROW_IOVMAX];
	int iovcnt = xrow_header_encode(packet, iov, 0);
	struct obuf_svp svp = obuf_create_svp(&block->obuf);
	for (int i = 0; i < iovcnt; ++i) {
		ERROR_INJECT(ERRINJ_WAL_WRITE_PARTIAL,
			{if (obuf_size(&block->obuf) > (1 << 14)) {
				obuf_rollback_to_svp(&block->obuf, &svp);
				return -1;}});
		if (obuf_dup(&block->obuf, iov[i].iov_base, iov[i].iov_len) <
		    iov[i].iov_len) {
			tnt_error(OutOfMemory, XLOG_FIXHEADER_SIZE,
				  "runtime arena", "xlog tx output buffer");
			obuf_rollback_to_svp(&block->obuf, &svp);
			return -1;
		}
	}
	assert(iovcnt <= XROW_IOVMAX);

	if (block->is_autocommit &&
	    obuf_size(&block->obuf) >= XLOG_TX_AUTOCOMMIT_THRESHOLD) {
		return xlog_tx_write(log);
	}
	return 0;
}

void
xlog_cursor_open(struct xlog_cursor *i, struct xlog *l)
{
	/* Open xlog tx cursor positioned after xlog meta */
	i->log = l;
	i->row_count = 0;
	afio_reader_create(&i->reader, l->f, false);
	afio_reader_seek(&i->reader, l->first_tx_offset, SEEK_SET);
	i->eof_read  = false;
	ibuf_create(&i->zbuf, &cord()->slabc,
		    XLOG_TX_AUTOCOMMIT_THRESHOLD);
	i->zdctx = ZSTD_createDStream();
	i->rpos = i->epos = NULL;
}

void
xlog_cursor_close(struct xlog_cursor *i)
{
	struct xlog *l = i->log;
	l->rows += i->row_count;
	/* Its bad, eof_read should be removed from xlog */
	l->eof_read = i->eof_read;
	/*
	 * Since we don't close the xlog
	 * we must rewind it to the last known
	 * good position if there was an error.
	 * Seek back to last known good offset.
	 */
	afio_reader_destroy(&i->reader);
	ibuf_destroy(&i->zbuf);
	ZSTD_freeDStream(i->zdctx);
	region_free(&fiber()->gc);
}

static int
xlog_cursor_next_row(struct xlog_cursor *i, struct xrow_header *row)
{
	/* Return row from xlog tx buffer */
	try {
		xrow_header_decode(row,
				   (const char **)&i->rpos,
				   (const char *)i->epos);
	} catch (ClientError *e) {
		if (i->log->dir->panic_if_error)
			throw;
		say_warn("failed to read row");
		return -1;
	}
	/* This should be moved to upper level */
	i->row_count++;

	if (i->row_count % 100000 == 0)
		say_info("%.1fM rows processed",
			 i->row_count / 1000000.);
	return 0;
}

/**
 * Read logfile contents using designated format, panic if
 * the log is corrupted/unreadable.
 *
 * @param i	iterator object, encapsulating log specifics.
 *
 * @retval 0    OK
 * @retval 1    EOF
 */
int
xlog_cursor_next(struct xlog_cursor *i, struct xrow_header *row)
{
	struct xlog *l = i->log;
	log_magic_t magic = 0;
	off_t magic_offset;

	assert(i->eof_read == false);

	if (i->rpos < i->epos) {
		/*
		 * Still more xrows in this tx batch, unpack the next
		 * row.
		 */
		if (!xlog_cursor_next_row(i, row))
			return 0;
	}

	/*
	 * Don't let gc pool grow too much. Yet to
	 * it before reading the next row, to make
	 * sure it's not freed along here.
	 */
	region_free_after(&fiber()->gc, 128 * 1024);

restart:
	magic_offset = i->reader.rpos;
	/* try to find next xlog tx magic */
	if (afio_reader_read(&i->reader, &magic, sizeof(magic)) <
	    (ssize_t)sizeof(magic))
		goto eof;

	while (magic != row_marker && magic != zrow_marker &&
	       magic != eof_marker) {
	       /* Magic not found, move to next position */
		char c;
		if (afio_reader_read(&i->reader, &c, 1) < 1) {
			say_debug("eof while looking for magic");
			goto eof;
		}
		magic = magic >> 8 |
			((log_magic_t) c & 0xff) << (sizeof(magic)*8 - 8);
	}
	if ((off_t)(magic_offset + sizeof(magic)) != i->reader.rpos)
		say_warn("skipped %jd bytes after 0x%08jx offset",
			 (intmax_t)(i->reader.rpos -
			           (magic_offset + sizeof(magic))),
			 (uintmax_t)magic_offset);
	magic_offset = i->reader.rpos;
	say_debug("magic found at 0x%08jx", (uintmax_t)magic_offset);

	int rc;
	/* Read xlog tx */
	rc = xlog_cursor_read_tx(i, magic);
	if (rc > 0)
		goto eof;
	if (rc < 0) {
		/* Error while tx reading */
		if (l->dir->panic_if_error)
			diag_raise();
		/*
		 * say_warn() is used and exception is not
		 * logged since an error may happen in local
		 * hot standby or replication mode, when it's
		 * caused by an attempt to read a partially
		 * written WAL.
		 */
		/* Return read position to pos after current found magic */
		afio_reader_seek(&i->reader, magic_offset, SEEK_SET);
		say_warn("failed to read row block");
		goto restart;
	}
	if (!xlog_cursor_next_row(i, row))
		return 0;
	goto restart;
eof:
	/*
	 * According to POSIX, if a partial element is read, value
	 * of the file position indicator for the stream is
	 * unspecified.
	 *
	 * Thus don't trust the current file position, seek to the
	 * last good position first.
	 *
	 * The only case of a fully read file is when eof_marker
	 * is present and it is the last record in the file. If
	 * eof_marker is missing, the caller must make the
	 * decision whether to switch to the next file or not.
	 */
	if (magic == eof_marker) {
		i->eof_read = true;
	} else {
		/*
		 * Row marker at the end of a file: a sign
		 * of a corrupt log file in case of
		 * recovery, but OK in case we're in local
		 * hot standby or replication relay mode
		 * (i.e. data is being written to the
		 * file.
		 */
	}
	/* No more rows. */
	return 1;
}

/* }}} */

/* {{{ struct xlog */

int
xlog_close(struct xlog *l)
{
	int r;

	if (l->mode == LOG_WRITE) {
		afio_appender_write(&l->appender, &eof_marker,
				    sizeof(log_magic_t));
		afio_appender_flush(&l->appender);
		/*
		 * Sync the file before closing, since
		 * otherwise we can end up with a partially
		 * written file in case of a crash.
		 * Do not sync if the file is opened with O_SYNC.
		 */
		if (! strchr(l->dir->open_wflags, 's'))
			xlog_sync(l);
	}

	afio_appender_destroy(&l->appender);
	r = afio_close(l->f, false);
	if (r < 0)
		say_syserror("%s: close() failed", l->filename);
	xlog_tx_destroy(&l->xlog_tx);
	free(l);
	return r;
}

/**
 * Free xlog memory and destroy it cleanly, without side
 * effects (for use in the atfork handler).
 */
void
xlog_atfork(struct xlog **lptr)
{
	struct xlog *l = *lptr;
	if (l) {
		/*
		 * Close the file descriptor STDIO buffer does not
		 * make its way into the respective file in
		 * fclose().
		 */
		afio_close(l->f, false);
		*lptr = NULL;
	}
}

static int
sync_cb(eio_req *req)
{
	struct afio *afio = (struct afio *) req->data;
	if (req->result) {
		errno = req->result;
		say_syserror("%s: fsync() failed",
			     afio_name(afio));
		errno = 0;
	}
	return 0;
}

static void
do_sync(eio_req *req)
{
	struct afio *afio = (struct afio *)req->data;
	req->result = afio_fdatasync(afio, false);
}

int
xlog_sync(struct xlog *l)
{
	if (l->dir->sync_is_async) {
		/*
		 * sync from another thread,
		 * but possibly we need to suppurt dup for afio to
		 */
		eio_custom(do_sync, 0, sync_cb, l->f);
	} else if (afio_fsync(l->f, false) < 0) {
		say_syserror("%s: fsync failed", l->filename);
		return -1;
	}
	return 0;
	afio_fsync(l->f, false);
	return 0;
}

#define SERVER_UUID_KEY "Server"
#define VCLOCK_KEY "VClock"

static int
xlog_write_meta(struct xlog *l)
{
	char *vstr = vclock_to_string(&l->vclock);
	if (!vstr)
		return -1;
	char *uuid = tt_uuid_str(l->dir->server_uuid);
	if (!uuid) {
		free(vstr);
		return -1;
	}
	size_t sz = strlen(l->dir->filetype) + strlen(v13) +
		    strlen(SERVER_UUID_KEY) + 2 +
		    strlen(uuid) + 1 +
		    strlen(VCLOCK_KEY) + 2 + strlen(vstr) + 2;
	char *dst;
	if (!(dst = (char *)afio_appender_reserve(&l->appender, sz + 1))) {
		free(vstr);
		return -1;
	}
	snprintf(dst, sz + 1, "%s%s" SERVER_UUID_KEY ": %s\n"
		 VCLOCK_KEY ": %s\n\n", l->dir->filetype, v13,
		 uuid, vstr);
	afio_appender_alloc(&l->appender, sz);
	afio_appender_flush(&l->appender);
	free(vstr);
	/* First block starts after meta */
	l->xlog_tx.offset = sz;
	return 0;
}

/**
 * Verify that file is of the given format.
 *
 * @param l		xlog object, denoting the file to check.
 * @param[out] errmsg   set if error
 *
 * @return 0 if success, -1 on error.
 */
static int
xlog_read_meta(struct xlog *l, int64_t signature)
{
	char filetype[32], version[32], buf[256];
	struct xdir *dir = l->dir;
	struct afio_reader reader;
	afio_reader_create(&reader, l->f, false);

	if (afio_gets(&reader, filetype, sizeof(filetype)) == NULL ||
	    afio_gets(&reader, version, sizeof(version)) == NULL) {
		tnt_error(XlogError, "%s: failed to read log file header",
			  l->filename);
		afio_reader_destroy(&reader);
		return -1;
	}
	if (strcmp(dir->filetype, filetype) != 0) {
		tnt_error(XlogError, "%s: unknown filetype", l->filename);
		afio_reader_destroy(&reader);
		return -1;
	}

	if (strcmp(v13, version) != 0 && strcmp(v12, version) != 0) {
		tnt_error(XlogError, "%s: unsupported file format version %s",
			  l->filename, version);
		afio_reader_destroy(&reader);
		return -1;
	}
	for (;;) {
		if (afio_gets(&reader, buf, sizeof(buf)) == NULL) {
			tnt_error(XlogError, "%s: failed to read log file "
				  "header", l->filename);
			afio_reader_destroy(&reader);
			return -1;
		}
		/** Empty line indicates the end of file header. */
		if (strcmp(buf, "\n") == 0)
			break;

		/* Parse RFC822-like string */
		char *end = buf + strlen(buf);
		if (end > buf && *(end - 1) == '\n')
			*(--end) = 0; /* skip \n */
		char *key = buf;
		char *val = strchr(buf, ':');
		if (val == NULL) {
			tnt_error(XlogError, "%s: invalid meta", l->filename);
			afio_reader_destroy(&reader);
			return -1;
		}
		*val++ = 0;
		while (isspace(*val))
			++val;	/* skip starting spaces */

		if (strcmp(key, SERVER_UUID_KEY) == 0) {
			if ((end - val) != UUID_STR_LEN ||
			    tt_uuid_from_string(val, &l->server_uuid) != 0) {
				tnt_error(XlogError, "%s: can't parse node UUID",
					  l->filename);
				afio_reader_destroy(&reader);
				return -1;
			}
		} else if (strcmp(key, VCLOCK_KEY) == 0){
			size_t offset = vclock_from_string(&l->vclock, val);
			if (offset != 0) {
				tnt_error(XlogError, "%s: invalid vclock at "
					  "offset %zd", l->filename, offset);
				afio_reader_destroy(&reader);
				return -1;
			}
		} else {
			/* Skip unknown key */
		}
	}

	if (!tt_uuid_is_nil(dir->server_uuid) &&
	    !tt_uuid_is_equal(dir->server_uuid, &l->server_uuid)) {
		tnt_error(XlogError, "%s: invalid server UUID",
			  l->filename);
		afio_reader_destroy(&reader);
		return -1;
	}
	/*
	 * Check the match between log file name and contents:
	 * the sum of vector clock coordinates must be the same
	 * as the name of the file.
	 */
	int64_t signature_check = vclock_sum(&l->vclock);
	if (signature_check != signature) {
		tnt_error(XlogError, "%s: signature check failed",
			  l->filename);
		afio_reader_destroy(&reader);
		return -1;
	}
	l->first_tx_offset = reader.rpos;
	afio_reader_destroy(&reader);
	return 0;
}

struct xlog *
xlog_open_stream(struct xdir *dir, int64_t signature, struct afio *file,
		 const char *filename)
{
	/*
	 * Check fopen() result the caller first thing, to
	 * preserve the errno.
	 */
	if (file == NULL) {
		tnt_error(SystemError, "%s: failed to open file", filename);
		return NULL;
	}

	struct xlog *l = (struct xlog *) calloc(1, sizeof(*l));

	auto log_guard = make_scoped_guard([=]{
		afio_close(file, false);
		free(l);
	});

	if (l == NULL) {
		tnt_error(OutOfMemory, sizeof(*l), "malloc", "struct xlog");
		return NULL;
	}

	l->f = file;
	snprintf(l->filename, PATH_MAX, "%s", filename);
	l->mode = LOG_READ;
	l->dir = dir;
	l->is_inprogress = false;
	l->eof_read = false;
	vclock_create(&l->vclock);

	if (xlog_read_meta(l, signature) != 0)
		return NULL;

	log_guard.is_active = false;
	return l;
}

struct xlog *
xlog_open(struct xdir *dir, int64_t signature)
{
	const char *filename = format_filename(dir, signature, NONE);
	struct afio *f = afio_file_open(filename, "rd");
	return xlog_open_stream(dir, signature, f, filename);
}

int
xlog_rename(struct xlog *l)
{
       char *filename = l->filename;
       char new_filename[PATH_MAX];
       char *suffix = strrchr(filename, '.');

       assert(l->is_inprogress);
       assert(suffix);
       assert(strcmp(suffix, inprogress_suffix) == 0);

       /* Create a new filename without '.inprogress' suffix. */
       memcpy(new_filename, filename, suffix - filename);
       new_filename[suffix - filename] = '\0';

       if (rename(filename, new_filename) != 0) {
               say_syserror("can't rename %s to %s", filename, new_filename);

               return -1;
       }
       l->is_inprogress = false;
       return 0;
}

/**
 * In case of error, writes a message to the server log
 * and sets errno.
 */
struct xlog *
xlog_create(struct xdir *dir, const struct vclock *vclock)
{
	char *filename;
	struct afio *f = NULL;
	struct xlog *l = NULL;

	int64_t signature = vclock_sum(vclock);
	assert(signature >= 0);
	assert(!tt_uuid_is_nil(dir->server_uuid));

	/*
	* Check whether a file with this name already exists.
	* We don't overwrite existing files.
	*/
	filename = format_filename(dir, signature, NONE);
	if (access(filename, F_OK) == 0) {
		errno = EEXIST;
		goto error;
	}

	/*
	 * Open the <lsn>.<suffix>.inprogress file.
	 * If it exists, open will fail. Always open/create
	 * a file with .inprogress suffix: for snapshots,
	 * the rename is done when the snapshot is complete.
	 * Fox xlogs, we can rename only when we have written
	 * the log file header, otherwise replication relay
	 * may think that this is a corrupt file and stop
	 * replication.
	 */
	filename = format_filename(dir, signature, INPROGRESS);
	f = afio_file_open(filename, dir->open_wflags);
	if (!f)
		goto error;
	say_info("creating `%s'", filename);
	l = (struct xlog *) calloc(1, sizeof(*l));
	if (l == NULL)
		goto error;
	l->f = f;
	afio_appender_create(&l->appender, f, false);
	snprintf(l->filename, PATH_MAX, "%s", filename);
	l->mode = LOG_WRITE;
	l->dir = dir;
	l->is_inprogress = true;
	/*  Makes no sense, but well. */
	l->eof_read = false;
	vclock_copy(&l->vclock, vclock);

	if (xlog_tx_create(&l->xlog_tx))
		goto error;

	if (xlog_write_meta(l) != 0)
		goto error;
	if (dir->suffix != INPROGRESS && xlog_rename(l))
		goto error;

	return l;
error:
	int save_errno = errno;
	say_syserror("%s: failed to open", filename);
	if (f != NULL) {
		afio_appender_destroy(&l->appender);
		afio_close(f, false);
		unlink(filename); /* try to remove incomplete file */
	}
	if (l) {
		obuf_destroy(&l->xlog_tx.obuf);
	}
	if (l && l->xlog_tx.zctx)
		ZSTD_freeCCtx(l->xlog_tx.zctx);
	free(l);
	errno = save_errno;
	return NULL;
}

/* }}} */

