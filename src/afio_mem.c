#include "afio_mem.h"
#include "afio.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "trivia/util.h"
#include "diag.h"
#include "box/errcode.h"

#define RETURN_ERROR(NAME, OP, ERRSTR, RESULT)\
{\
	char errmsg[512]; \
	snprintf(errmsg, sizeof(errmsg), "%s %s error: %s", \
			 NAME, #OP, ERRSTR); \
		diag_set(ClientError, ER_SYSTEM, errmsg); \
		return RESULT; \
}

struct afio_mem {
	struct afio base;
	char *data;
	size_t size;
};

static int
afio_mem_close(struct afio *afio)
{
	free(afio);
	return 0;
}

static ssize_t
afio_mem_pwrite(struct afio *afio, const void *data, size_t count, off_t pos)
{
	struct afio_mem *mem = (struct afio_mem *)afio;
	if (pos < 0 || pos > (off_t)mem->size) {
		RETURN_ERROR(afio_name(afio), write, "Invalid parameters", -1);
	}
	size_t to_write = MIN(count, mem->size - pos);
	memcpy(mem->data + pos, data, count);
	return to_write;
}


static ssize_t
afio_mem_pread(struct afio *afio, void *data, size_t count, off_t pos)
{
	struct afio_mem *mem = (struct afio_mem *)afio;
	if (pos < 0 || pos > (off_t)mem->size) {
		RETURN_ERROR(afio_name(afio), read, "Invalid parameters", -1);
	}
	size_t to_read = MIN(count, mem->size - pos);
	memcpy(data, mem->data + pos, to_read);
	return to_read;
}

static struct afio_vtab afio_mem_vtab  = {
	.close = afio_mem_close,
	.pwrite = afio_mem_pwrite,
	.pread = afio_mem_pread,
};

struct afio *
afio_mem_open(char *data, size_t size, const char *mode, const char *name)
{
	(void) mode;
	struct afio_mem *mem;
	mem = (struct afio_mem *)calloc(1, sizeof(*mem));
	if (!mem) {
		RETURN_ERROR(name, alloc, strerror(errno), NULL);
	}
	mem->data = data;
	mem->size = size;
	snprintf(mem->base.name, PATH_MAX, "%s", name);
	mem->base.sync_vtab = afio_mem_vtab;
	mem->base.async_vtab = afio_mem_vtab;
	return &mem->base;
}

