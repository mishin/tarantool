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
#include "afio.h"
#include "afio_mem.h"
#include "afio_posix.h"

#include <limits.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "fiber.h"
#include "diag.h"
#include "box/errcode.h"

struct afio *
afio_file_open(const char *name, const char *mode)
{
	return afio_posix_open(name, mode, false);
}

int
afio_close(struct afio *afio, bool async)
{
	int rc;
	if (async)
		rc = afio->async_vtab.close(afio);
	else
		rc = afio->sync_vtab.close(afio);
	return rc;
}

#define AFIO_UNIMPLEMENTED_ER(op, res) \
{	char errmsg[512];\
	snprintf(errmsg, sizeof(errmsg),\
		 "Unimplemented afio op: %s", #op);\
	diag_set(ClientError, ER_SYSTEM, errmsg);\
	return res;\
}

ssize_t
afio_pwrite(struct afio *afio, const void *buf, size_t count,
	    off_t pos, bool async)
{
	struct afio_vtab *vtab = async? &afio->async_vtab: &afio->sync_vtab;
	if (!vtab->pwrite)
		AFIO_UNIMPLEMENTED_ER(pwrite, -1);
	return vtab->pwrite(afio, buf, count, pos);
}

ssize_t
afio_pread(struct afio *afio, void *buf, size_t count, off_t pos, bool async)
{
	struct afio_vtab *vtab = async? &afio->async_vtab: &afio->sync_vtab;
	if (!vtab->pread)
		AFIO_UNIMPLEMENTED_ER(pread, -1);
	return vtab->pread(afio, buf, count, pos);
}

int
afio_ftruncate(struct afio *afio, off_t len, bool async)
{
	struct afio_vtab *vtab = async? &afio->async_vtab: &afio->sync_vtab;
	if (!vtab->ftruncate)
		AFIO_UNIMPLEMENTED_ER(ftruncate, -1);
	return vtab->ftruncate(afio, len);
}
int
afio_fsync(struct afio *afio, bool async)
{
	struct afio_vtab *vtab = async? &afio->async_vtab: &afio->sync_vtab;
	if (!vtab->fsync)
		AFIO_UNIMPLEMENTED_ER(fsync, -1);
	return vtab->fsync(afio);
}

int
afio_fdatasync(struct afio *afio, bool async)
{
	struct afio_vtab *vtab = async? &afio->async_vtab: &afio->sync_vtab;
	if (!vtab->fdatasync)
		AFIO_UNIMPLEMENTED_ER(fdatasync, -1);
	return vtab->fdatasync(afio);
}

char *
afio_name(struct afio *afio)
{
	return afio->name;
}


#define ALIGN_MASK ((1 << 9) - 1)
#define ALIGN_SIZE (1 << 9)
#define ALIGN_DOWN(VAL) ((VAL) & ~ALIGN_MASK)
#define ALIGN_UP(VAL) ALIGN_DOWN((VAL) + ALIGN_MASK)
#define ALIGN_PREALLOC ALIGN_SIZE * (32 + 1)

int
afio_appender_create(struct afio_appender *appender,
		     struct afio *afio, bool async)
{
	obuf_create(&appender->obuf, &cord()->slabc, ALIGN_PREALLOC);
	/* Allocate and setup buffer for file tail (last unaligned size part( */
	ibuf_create(&appender->tail, &cord()->slabc, ALIGN_SIZE * 2);
	void *tail = ibuf_alloc(&appender->tail, ALIGN_SIZE * 2);
	appender->tail.rpos = appender->tail.wpos =
		(void *)ALIGN_UP((intptr_t)tail);
	appender->afio = afio;
	appender->async = async;
	appender->size = 0;
	appender->pos = appender->size;
	return 0;
}

void *
afio_appender_reserve(struct afio_appender *appender, size_t count)
{
	/*
	 * Reserve some space in write buffer to store up to count bytes.
	 * We should reserve some more space for aligned file operations.
	 * Aligned buf ptrs should be mapped to aligned file postions
	 */
	if (appender->size == (size_t)appender->pos) {
		/*
		 * Write buffer is empty,
		 * reserve space for rounded up count bytes + 2 * ALIGN_SIZE
		 * (one for buf ptr aligment (up to ALIGN_SIZE - 1 bytes),
		 * second for file position aligment (up to ALIGN_SIZE - 1 bytes)
		 */
		void *dst = obuf_reserve(&appender->obuf,
					 ALIGN_UP(count) + 2 * ALIGN_SIZE);
		/* How many bytes should be skipped for aligned ptr */
		size_t fixup = ALIGN_UP((intptr_t)dst) - (intptr_t)dst;
		dst += fixup;
		obuf_alloc(&appender->obuf, fixup);
		/* How many bytes should be skipped to reach file posiion */
		size_t tail_size = appender->pos & ALIGN_MASK;
		if (tail_size) {
			/*
			 * Tail isn't zero, initialize write buffer
			 * with preserved file tail data
			 * (copy it to head of current write buffer)
			 * */
			memcpy(dst, appender->tail.rpos, tail_size);
			dst += tail_size;
			obuf_alloc(&appender->obuf, tail_size);
		}
		return dst;
	}
	/* Last iov in write buffer */
	struct iovec *last_iov = appender->obuf.iov + appender->obuf.pos;
	/*
	 * Reserve up to count bytes + some additional space (see comment above)
	 */
	void *dst = obuf_reserve(&appender->obuf,
				 ALIGN_UP(count) + 2 * ALIGN_SIZE);
	if (dst == last_iov->iov_base + last_iov->iov_len) {
		/* Append to current iov, nothing to do with aligment */
		return dst;
	}
	/*
	 * First skip some bytes to align mem buffer,
	 * then skip some bytes to reach file pos
	 */
	size_t fixup = ALIGN_UP((intptr_t)dst) - (intptr_t)dst;
	dst += fixup;
	obuf_alloc(&appender->obuf, fixup);
	size_t tail_size = appender->pos & ALIGN_MASK;
	dst += tail_size;
	obuf_alloc(&appender->obuf, tail_size);
	return dst;
}

void *
afio_appender_alloc(struct afio_appender *appender, size_t count)
{
	/* Reserve space */
	void *dst = afio_appender_reserve(appender, count);
	if (!dst)
		return NULL;
	/* Consume space in obuf */
	void *res = obuf_alloc(&appender->obuf, count);
	/* Update write pos */
	appender->pos += count;
	return res;
}

ssize_t
afio_appender_write(struct afio_appender *appender, const void *data,
		    size_t count)
{
	/* Alloc space in write buffer */
	void *dst = afio_appender_alloc(appender, count);
	if (!dst)
		return -1;
	/* Fill with data */
	memcpy(dst, data, count);
	return count;
}

void
afio_appender_reset(struct afio_appender *appender)
{
	appender->pos = appender->size;
	obuf_reset(&appender->obuf);
}

/*
 * Setup iovec array from appender write buffer for writing
 * Returns count of new data to be flushed
 */
static ssize_t
afio_appender_prepare_flush(struct afio_appender *appender,
			    struct iovec *iov)
{
	/* Some data will be rewritten */
	ssize_t to_flush = -(appender->size & ALIGN_MASK);
	struct iovec *src_iov = appender->obuf.iov;
	struct iovec *dst_iov = iov;

	for (; src_iov->iov_len; ++src_iov, ++dst_iov) {
		/* Align base for iov and adjust len */
		dst_iov->iov_base = (void *)ALIGN_UP((intptr_t)src_iov->iov_base);
		dst_iov->iov_len = src_iov->iov_len -
				   (dst_iov->iov_base - src_iov->iov_base);
		to_flush += dst_iov->iov_len;
	}
	dst_iov->iov_len = 0;

	/*
	 * iov can have not fullfilled first and last chunks of data
	 * in this cases we will steal first chunk and concat
	 * to previous iov to have fullfilled aligned iovs
	 */
	dst_iov = iov;
	for (; dst_iov->iov_len; ++dst_iov) {
		size_t tail = dst_iov->iov_len & ALIGN_MASK;
		struct iovec *next_iov = dst_iov + 1;
		if (tail && next_iov->iov_len) {
			/* Not fullfilled tail and there is not last iov */
			memcpy(dst_iov->iov_base + dst_iov->iov_len,
			       next_iov->iov_base + tail,
			       ALIGN_SIZE - tail);
			/* Steal datas */
			next_iov->iov_base += ALIGN_SIZE;
			next_iov->iov_len -= ALIGN_SIZE;
			/* iov tail was counted twice, fix it */
			to_flush -= tail;
		}
		/* Len shoud be aligned if any */
		dst_iov->iov_len = ALIGN_UP(dst_iov->iov_len);
	}
	return to_flush;
}

ssize_t
afio_appender_flush(struct afio_appender *appender)
{
	if (appender->pos == (off_t)appender->size)
		return 0;
	ssize_t to_flush;
	struct iovec write_iov[SMALL_OBUF_IOV_MAX + 1];
	to_flush = afio_appender_prepare_flush(appender, write_iov);
	assert(to_flush == (ssize_t)(appender->pos - appender->size));

	/* Aligned file write pos */
	off_t wpos = ALIGN_DOWN(appender->size);
	struct iovec *iov = write_iov;
	/* Some bytes will be rewritten */
	ssize_t flushed = -(appender->size & ALIGN_MASK);
	/* last written byte from iovec array */
	void *last_written = NULL;
	for (; iov->iov_len; ++iov) {
		ssize_t written = afio_pwrite(appender->afio,
					      iov->iov_base,
					      iov->iov_len, wpos,
					      appender->async);
		if (written < 0)
			return -1;
		/*
		 * base + written isn't written,
		 * this is first unwritten byte
		 */
		last_written = iov->iov_base + written - 1;
		flushed += written;
		wpos += written;
		if (written < (ssize_t)iov->iov_len) {
			break;
		}
	}
	/*
	 * Some data should be truncated,
	 * keep in mind we can flush more than can be flushed
	 */
	flushed = MIN(flushed, to_flush);
	/* Adjust size and position */
	appender->size = appender->size + flushed;
	appender->pos = appender->size;
	if (appender->size & ALIGN_MASK) {
		/*
		 * File has not fullfiled tail,
		 * preserve it in tail buffer
		 */
		memcpy(appender->tail.wpos,
		       (void *)ALIGN_DOWN((intptr_t)last_written),
		       ALIGN_SIZE);
		obuf_reset(&appender->obuf);
		if (afio_ftruncate(appender->afio, appender->size,
				   appender->async) < 0)
			return -1;
	} else {
		obuf_reset(&appender->obuf);
	}
	return flushed;
}

off_t
afio_appender_ftruncate(struct afio_appender *appender, off_t len)
{
	afio_appender_reset(appender);
	appender->size = len;
	appender->pos = len;
	if (appender->size & ALIGN_MASK) {
		memset(appender->tail.wpos, 0, ALIGN_SIZE);
		ssize_t readen;
		readen = afio_pread(appender->afio, appender->tail.wpos,
				    ALIGN_SIZE, ALIGN_DOWN(appender->size),
				    appender->async);
		if (readen < 0)
			return -1;
	}
	return afio_ftruncate(appender->afio, len, appender->async);
}

void
afio_appender_destroy(struct afio_appender *appender)
{
	ibuf_destroy(&appender->tail);
	obuf_destroy(&appender->obuf);
}

int
afio_reader_create(struct afio_reader *reader,
		   struct afio *afio, bool async)
{
	/* Create reader */
	ibuf_create(&reader->ibuf, &cord()->slabc, ALIGN_PREALLOC);
	reader->afio = afio;
	reader->async = async;
	reader->pos = 0;
	reader->rpos = 0;
	return 0;
}

ssize_t
afio_reader_load(struct afio_reader *reader,
		   void **data, size_t count)
{
	if (reader->rpos >= reader->pos &&
	    reader->rpos + count <= reader->pos + ibuf_used(&reader->ibuf)) {
		/* We have data in read buf */
		*data = reader->ibuf.rpos + reader->rpos - reader->pos;
		reader->rpos += count;
		return count;
	}
	ibuf_reset(&reader->ibuf);
	/* Count of bytes to be readen */
	size_t to_read;
	to_read = ALIGN_UP(reader->rpos + count) -ALIGN_DOWN(reader->rpos);
	to_read = MAX(to_read, ALIGN_SIZE * 8);
	if (!ibuf_reserve(&reader->ibuf, to_read + ALIGN_SIZE))
		return -1;
	/* Align position in read buffer */
	reader->ibuf.wpos = reader->ibuf.rpos =
		(void *)(ALIGN_UP((intptr_t)reader->ibuf.buf));
	/* file pos to start reading */
	reader->pos = ALIGN_DOWN(reader->rpos);
	ssize_t readen = afio_pread(reader->afio, reader->ibuf.wpos,
				    to_read, reader->pos, reader->async);
	if (readen < 0)
		return readen;
	/* Advence read buffer */
	ibuf_alloc(&reader->ibuf, readen);
	/* How many bytes we should skip in read buffer for logical pos */
	ssize_t skip = reader->rpos - reader->pos;
	if (readen <= skip)
		return 0;
	/* Setup pointer and return count of bytes */
	*data = reader->ibuf.rpos + skip;
	readen = MIN(readen - skip, (ssize_t)count);
	reader->rpos += readen;
	return readen;
}

ssize_t
afio_reader_read(struct afio_reader *reader,
		 void *data, size_t count)
{
	void *src;
	ssize_t loaded = afio_reader_load(reader, &src, count);
	if (loaded >= 0)
		memcpy(data, src, loaded);
	return loaded;
}

off_t
afio_reader_seek(struct afio_reader *reader, off_t offset, int whence)
{
	/* Update read pos */
	switch (whence) {
	case SEEK_SET: reader->rpos = offset; break;
	case SEEK_CUR: reader->rpos += offset; break;
	case SEEK_END:
		/* For stream reader we can't know exact file size */
		diag_set(ClientError, ER_SYSTEM, "Not supported");
		return -1;
	default:
		diag_set(ClientError, ER_SYSTEM, "Invalid parameter");
		return -1;
	}
	if (reader->rpos < 0) {
		diag_set(ClientError, ER_SYSTEM, "Invalid parameter");
		return -1;
	}
	return reader->rpos;
}

void
afio_reader_destroy(struct afio_reader *reader)
{
	ibuf_destroy(&reader->ibuf);
}

char *
afio_gets(struct afio_reader *reader, char *str, size_t size){
	size_t len = 0;
	while (len < size - 1) {
		ssize_t readen = afio_reader_read(reader, str + len, 1);
		if (readen < 0)
			return NULL;
		if (!readen)
			break;
		if (str[len++] == '\n')
			break;
	}
	str[len] = '\0';
	return len ? str: NULL;
}

