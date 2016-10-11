#include "afio_posix.h"
#include "afio.h"

#include <limits.h>

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include <sys/stat.h>
#include <fcntl.h>
#include "trivia/util.h"

#include "diag.h"
#include "box/errcode.h"
#include "coeio_file.h"

#define RETURN_ERROR(NAME, OP, RESULT) \
{ \
	char errmsg[512]; \
	snprintf(errmsg, sizeof(errmsg), \
		 "%s %s error: %s", \
		 NAME, #OP, strerror(errno)); \
		diag_set(ClientError, ER_SYSTEM, errmsg); \
	return RESULT; \
}

struct afio_posix {
	struct afio base;
	int fd;
};

static int
afio_posix_close(struct afio *afio)
{
	int fd = ((struct afio_posix *)afio)->fd;
	free(afio);
	if (!close(fd))
		return 0;
	RETURN_ERROR(afio_name(afio), close, -1);
}

static int
afio_posix_co_close(struct afio *afio)
{
	int fd = ((struct afio_posix *)afio)->fd;
	free(afio);
	if (!coeio_close(fd))
		return 0;
	RETURN_ERROR(afio_name(afio), close, -1);
}

static ssize_t
afio_posix_pwrite(struct afio *afio, const void *data,
		  size_t count,
		  off_t pos)
{
	int fd = ((struct afio_posix *)afio)->fd;
	ssize_t written = pwrite(fd, data, count, pos);
	if (written > 0)
		return written;
	RETURN_ERROR(afio_name(afio), write, -1);
}

static ssize_t
afio_posix_co_pwrite(struct afio *afio, const void *data,
		     size_t count,
		     off_t pos)
{
	int fd = ((struct afio_posix *)afio)->fd;
	ssize_t written = coeio_pwrite(fd, data, count, pos);
	if (written > 0)
		return written;
	RETURN_ERROR(afio_name(afio), write, -1);
}

static ssize_t
afio_posix_pread(struct afio *afio, void *data, size_t count,
		 off_t pos)
{
	int fd = ((struct afio_posix *)afio)->fd;
	ssize_t readen = pread(fd, data, count, pos);
	if (readen >= 0)
		return readen;
	RETURN_ERROR(afio_name(afio), read, -1);
}

static ssize_t
afio_posix_co_pread(struct afio *afio, void *data, size_t count,
		 off_t pos)
{
	int fd = ((struct afio_posix *)afio)->fd;
	ssize_t readen = coeio_pread(fd, data, count, pos);
	if (readen >= 0)
		return readen;
	RETURN_ERROR(afio_name(afio), read, -1);
}

static int
afio_posix_ftruncate(struct afio *afio, off_t length)
{
	int fd = ((struct afio_posix *)afio)->fd;
	off_t new_length = ftruncate(fd, length);
	if (new_length >= 0)
		return new_length;
	RETURN_ERROR(afio_name(afio), ftruncate, -1);
}

static int
afio_posix_co_ftruncate(struct afio *afio, off_t length)
{
	int fd = ((struct afio_posix *)afio)->fd;
	off_t new_length = coeio_ftruncate(fd, length);
	if (new_length >= 0)
		return new_length;
	RETURN_ERROR(afio_name(afio), ftruncate, -1);
}

static int
afio_posix_fsync(struct afio *afio)
{
	int fd = ((struct afio_posix *)afio)->fd;
	if (!fsync(fd))
		return 0;
	RETURN_ERROR(afio_name(afio), fsync, -1);
}

static int
afio_posix_co_fsync(struct afio *afio)
{
	int fd = ((struct afio_posix *)afio)->fd;
	if (!coeio_fsync(fd))
		return 0;
	RETURN_ERROR(afio_name(afio), fsync, -1);
}

static int
afio_posix_fdatasync(struct afio *afio)
{
	int fd = ((struct afio_posix *)afio)->fd;
	if (!fdatasync(fd))
		return 0;
	RETURN_ERROR(afio_name(afio), fdatasync, -1);
}

static int
afio_posix_co_fdatasync(struct afio *afio)
{
	int fd = ((struct afio_posix *)afio)->fd;
	if (!coeio_fdatasync(fd))
		return 0;
	RETURN_ERROR(afio_name(afio), fdatasync, -1);
}

static struct afio_vtab afio_posix_sync_vtab = {
	.close = afio_posix_close,
	.pwrite = afio_posix_pwrite,
	.pread = afio_posix_pread,
	.ftruncate = afio_posix_ftruncate,
	.fsync = afio_posix_fsync,
	.fdatasync = afio_posix_fdatasync,
};

static struct afio_vtab afio_posix_async_vtab = {
	.close = afio_posix_co_close,
	.pwrite = afio_posix_co_pwrite,
	.pread = afio_posix_co_pread,
	.ftruncate = afio_posix_co_ftruncate,
	.fsync = afio_posix_co_fsync,
	.fdatasync = afio_posix_co_fdatasync,
};

static int
get_flags(const char *mode)
{
	int flags = 0;
	int rw_mode = 0;

	while (*mode) {
		switch (*mode) {
		case 'c': flags |= O_CREAT; break;
		case 't': flags |= O_TRUNC; break;
		case 'x': flags |= O_EXCL; break;
		case 'r': rw_mode |= 0x01; break;
		case 'w': rw_mode |= 0x02; break;
		case 'd': flags |= O_DIRECT; break;
		case 's': flags |= O_SYNC; break;
		case 'S': flags |= O_DSYNC; break;
		case 'e': flags |= O_CLOEXEC; break;
		}
		++mode;
	}
	if (rw_mode == 0x03)
		flags |= O_RDWR;
	if (rw_mode == 0x02)
		flags |= O_WRONLY;
	if (rw_mode == 0x01)
		flags |= O_RDONLY;
	return flags;
}

struct afio *
afio_posix_open(const char *name, const char *mode, bool async)
{
	struct afio_posix *afio_posix;
	afio_posix = (struct afio_posix *)calloc(1, sizeof(*afio_posix));
	if (!afio_posix) {
		RETURN_ERROR(name, alloc, NULL);
	}

	if ((afio_posix->fd = async?
	    coeio_open(name, get_flags(mode), 0644):
	    open(name, get_flags(mode), 0644)) < 0) {
		free(afio_posix);
		RETURN_ERROR(name, open, NULL);
	}

	snprintf(afio_posix->base.name, PATH_MAX, "%s", name);
	afio_posix->base.sync_vtab = afio_posix_sync_vtab;
	afio_posix->base.async_vtab = afio_posix_async_vtab;
	return &afio_posix->base;
}

