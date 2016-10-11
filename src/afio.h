#ifndef TARANTOOL_AFIO_H_INCLUDED
#define TARANTOOL_AFIO_H_INCLUDED
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
#include <limits.h>
#include <sys/types.h>

#include <stdint.h>

#include "small/ibuf.h"
#include "small/obuf.h"

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

struct afio;

/* Functions to handle an afio object */
struct afio_vtab {
	int (*close)(struct afio *);
	ssize_t (*pwrite)(struct afio *, const void *, size_t, off_t);
	ssize_t (*pread)(struct afio *, void *, size_t, off_t);
	int (*ftruncate)(struct afio *, off_t);
	int (*fsync)(struct afio *);
	int (*fdatasync)(struct afio *);
};

/* Afio struct */
struct afio {
	/* Blocking methods */
	struct afio_vtab sync_vtab;
	/* Async methods */
	struct afio_vtab async_vtab;
	/* Associated name */
	char name[PATH_MAX];
};

/*
 * Create afio based on file
 */
struct afio *
afio_file_open(const char *name, const char *mode);

/*
 * Create afio based on memory, data should persist for afio lifetime
 */
struct afio*
afio_mem_open(char *data, size_t size, const char *mode, const char *name);

/*
 * Close afio
 */
int
afio_close(struct afio *afio, bool async);

/*
 * Write up to count bytes on pos to afio
 */
ssize_t
afio_pwrite(struct afio *afio, const void *buf, size_t count,
	    off_t pos, bool asnyc);

/*
 * Read up to count bytes from file pos
 */
ssize_t
afio_pread(struct afio *afio, void *buf, size_t count, off_t pos, bool async);

/*
 * Truncate file
 */
int
afio_ftruncate(struct afio *afio, off_t len, bool async);

/*
 * Sync file
 */
int
afio_fsync(struct afio *afio, bool async);

/*
 * Data sync for file
 */
int
afio_fdatasync(struct afio *afio, bool async);

/*
 * Return associated name
 */
char *
afio_name(struct afio *afio);

/* Sequental file appender struct */
struct afio_appender {
	struct afio *afio;
	/* Current file size (stored) */
	size_t size;
	/* Current write pos */
	off_t pos;
	/* Internal write buffer */
	struct obuf obuf;
	/* File tail buffer */
	struct ibuf tail;
	/* True if appender should be async */
	bool async;
};

/* Create a file appender */
int
afio_appender_create(struct afio_appender *appender,
		     struct afio *afio, bool async);

/*
 * Prepare appender internal buffer to store up to count bytes.
 * Returns pointer to reserved space
 */
void *
afio_appender_reserve(struct afio_appender *appender, size_t count);

/*
 * Alloc count bytes from write buffer, space may be reserved before use.
 * Space will be stored on disk after flush.
 * Returns pointer to allocated space
 */
void *
afio_appender_alloc(struct afio_appender *appender, size_t count);

/*
 * Alloc count bytes and fill it with data.
 * Return count of copied bytes
 */
ssize_t
afio_appender_write(struct afio_appender *appender,
		    const void *data, size_t count);

/*
 * Reset internal write buffer without any offloading to backing store
 */
void
afio_appender_reset(struct afio_appender *appender);

/*
 * Flush write buffer to backing store
 */
ssize_t
afio_appender_flush(struct afio_appender *appender);

/*
 * Truncate file, write buffer will be silently discarded. Write pos
 * sets to file size.
 * Returns new file size.
 */
off_t
afio_appender_ftruncate(struct afio_appender *appender, off_t len);

/* Destroy file appender struct, free write buffer memory */
void
afio_appender_destroy(struct afio_appender *appender);

/*
 * afio file reader struct
 */
struct afio_reader {
	struct afio *afio;
	/* Current read pos */
	off_t pos;
	/* Position from where read buffer mapped is */
	off_t rpos;
	/* Read buffer */
	struct ibuf ibuf;
	/* True if reader should afio in async mode */
	bool async;
};

/* Create file reader object */
int
afio_reader_create(struct afio_reader *reader,
		   struct afio *afio, bool async);

/*
 * Load up to count bytes from file into internal read buffer.
 * Pointer to start of loaded space will be return in data ptr.
 * Return count of loaded bytes
 */
ssize_t
afio_reader_load(struct afio_reader *reader,
		 void **data, size_t count);

/*
 * Load up to count bytes into internal read buffer and copy it to data
 */
ssize_t
afio_reader_read(struct afio_reader *reader,
		 void *data, size_t count);

/*
 * Update file read pos
 */
off_t
afio_reader_seek(struct afio_reader *reader, off_t offset, int whence);

/*
 * Destroy read buffer
 */
void
afio_reader_destroy(struct afio_reader *reader);

/*
 * Read string from file, (fgets behaviour)
 */
char *
afio_gets(struct afio_reader *reader, char *str, size_t size);

#if defined(__cplusplus)
}	/* extern "C" */
#endif

#endif
