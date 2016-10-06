#include "xlog_parser.h"

#include <ctype.h>

#include "msgpuck/msgpuck.h"

#include <box/xlog.h>
#include <box/xrow.h>
#include <box/iproto_constants.h>
#include <box/tuple.h>
#include <box/lua/tuple.h>
#include <lua/msgpack.h>
#include <lua/utils.h>

/*
extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}*/ /* extern "C" */

/* {{{ Helpers */

static box_tuple_format_t *fmt = NULL;
static uint32_t CTID_STRUCT_FFI_XLOG_CURSOR_REF = 0;
static const char *xloglib_name = "xlog";

static int
lbox_pushffixlog(struct lua_State *L, struct ffi_xlog_cursor *cur)
{
	struct ffi_xlog_cursor **pcur = NULL;
	pcur = (struct ffi_xlog_cursor **)luaL_pushcdata(L,
			CTID_STRUCT_FFI_XLOG_CURSOR_REF);
	*pcur = cur;
	return 1;
}

static struct ffi_xlog_cursor *
lbox_checkffixlog(struct lua_State *L, int narg, const char *src)
{
	uint32_t ctypeid; (void )src;
	void *data = NULL;
	data = (struct ffi_xlog_cursor *)luaL_checkcdata(L, narg, &ctypeid);
	assert(ctypeid == CTID_STRUCT_FFI_XLOG_CURSOR_REF);
	if (ctypeid != (uint32_t )CTID_STRUCT_FFI_XLOG_CURSOR_REF) {
		/* TODO */
		luaL_error(L, "bad usage");
	}
	return *(struct ffi_xlog_cursor **)data;
}

static int
luamp_decode_verify(struct lua_State *L, struct luaL_serializer *cfg,
		    const char **beg, const char *end)
{
	const char *tmp = *beg;
	if (mp_check(&tmp, end))
		return -1;
	luamp_decode(L, cfg, beg);
	return 1;
}

/* }}} */

/* {{{ Internal */

static int
parse_body_kv(struct lua_State *L, const char **beg, const char *end)
{
	if (mp_typeof(**beg) != MP_UINT) {
		/* That means we have broken package */
		return -1;
	}
	char buf[32];
	uint32_t v = mp_decode_uint(beg);
	if (v < IPROTO_KEY_MAX && iproto_key_strs[v] &&
	    iproto_key_strs[v][0]) {
		sprintf(buf, "%s", iproto_key_strs[v]);
	} else {
		sprintf(buf, "unknown_key#%u", v);
	}
	lua_pushstring(L, buf);
	switch (v) {
	case IPROTO_KEY:
	case IPROTO_TUPLE:
	case IPROTO_OPS:
		if (mp_typeof(**beg) == MP_ARRAY) {
			if (fmt == NULL)
				fmt = box_tuple_format_default();
			if (fmt != NULL) {
				const char *tuple_beg = *beg;
				mp_next(beg);
				struct tuple *tuple = NULL;
				assert(fmt != NULL);
				tuple = box_tuple_new(fmt, tuple_beg, *beg);
				if (!tuple) {
					lbox_error(L);
					return -1;
				}
				lbox_pushtuple(L, tuple);
			}
		}
	default:
		if (luamp_decode_verify(L, luaL_msgpack_default, beg, end) == -1)
			lua_pushstring(L, "error");
	}
	lua_settable(L, -3);
	return 0;
}

static int
parse_body(struct lua_State *L, const char *ptr, size_t len)
{
	const char **beg = &ptr;
	const char *end = ptr + len;
	if (mp_typeof(**beg) != MP_MAP) {
		return -1;
	}
	uint32_t size = mp_decode_map(beg);
	uint32_t i;
	for (i = 0; i < size && *beg < end; i++) {
		if (parse_body_kv(L, beg, end) == -1) {
			/* TODO ERROR */
			break;
		}
	}
	if (i != size)
		say_warn("warning: decoded %u values from"
			 " MP_MAP, %u expected", i, size);
	return 0;
}

static int
next_row(struct lua_State *L, xlog_cursor *cur) {
	struct xrow_header row;
	try {
		if (xlog_cursor_next(cur, &row) != 0)
			return -1;
	} catch (Exception *) {
		return lbox_error(L);
	}

	lua_pushinteger(L, row.lsn);
	lua_newtable(L);
	lua_pushstring(L, "HEADER");

	lua_newtable(L);
	lua_pushstring(L, "type");
	if (row.type < IPROTO_TYPE_STAT_MAX && iproto_type_strs[row.type]) {
		lua_pushstring(L, iproto_type_strs[row.type]);
	} else {
		char buf[32];
		sprintf(buf, "UNKNOWN#%u", row.type);
		lua_pushstring(L, buf);
	}
	lua_settable(L, -3); /* type */
	lua_pushstring(L, "lsn");
	lua_pushinteger(L, row.lsn);
	lua_settable(L, -3); /* lsn */
	lua_pushstring(L, "server_id");
	lua_pushinteger(L, row.server_id);
	lua_settable(L, -3); /* server_id */
	lua_pushstring(L, "timestamp");
	lua_pushnumber(L, row.tm);
	lua_settable(L, -3); /* timestamp */

	lua_settable(L, -3); /* HEADER */

	for (int i = 0; i < row.bodycnt; i++) {
		if (i == 0) {
			lua_pushstring(L, "BODY");
		} else {
			char buf[8];
			sprintf(buf, "BODY%d", i + 1);
			lua_pushstring(L, buf);
		}

		lua_newtable(L);
		parse_body(L, (char *)row.body[i].iov_base,
			   row.body[i].iov_len);
		lua_settable(L, -3);  /* BODY */
	}
	return 0;
}

/* }}} */

/* {{{ Xlog Parser */

static int
lbox_xlog_parser_gc(struct lua_State *L)
{
	struct ffi_xlog_cursor *log = lbox_checkffixlog(L, 1, "");

	if (log->xlobject) {
		xlog_close(log->xlobject);
		log->xlobject = NULL;
	}
	if (log->xlobject) {
		xlog_cursor_close(log->xlcobject);
		free(log->xlcobject);
		log->xlcobject = NULL;
	}
	free(log);
	return 0;
}

static int
lbox_xlog_parser_iterate(struct lua_State *L)
{
	struct ffi_xlog_cursor *log = lbox_checkffixlog(L, 1, "bad pairs argument");
	// int i = luaL_checkinteger(L, 2);

	// lua_pushinteger(L, i + 1);
	if (next_row(L, log->xlcobject) == 0)
		return 2;
	return 0;
}

/* }}} */

struct xlog *
lbox_initxlog(FILE *f, const char *filename)
{
	xdir *dir = (xdir *)calloc(1, sizeof(xdir));
	if (dir == NULL)
		tnt_raise(OutOfMemory, sizeof(xdir), "malloc", "struct xdir");
	dir->panic_if_error = false;
	dir->server_uuid == NULL;

	xlog *log = (xlog *)calloc(1, sizeof(xlog));
	if (log == NULL)
		tnt_raise(OutOfMemory, sizeof(xlog), "malloc", "struct xlog");

	log->f = f;
	log->dir = dir;
	log->mode = LOG_READ;
	log->eof_read = false;
	log->is_inprogress = false;
	vclock_create(&log->vclock);
	strncpy(log->filename, filename, PATH_MAX + 1);
	return log;
}

static void
lbox_xlog_skip_header(struct lua_State *L, FILE *f, const char *filename)
{
	char buf[256];
	for (;;) {
		if (fgets(buf, sizeof(buf), f) == NULL) {
			luaL_error(L, "%s: failed to read log file header",
				   filename);
		}
		/** Empty line indicates the end of file header. */
		if (strcmp(buf, "\n") == 0)
			break;
		/* Skip header */
	}
}

static int
lbox_xlog_parser_open_pairs(struct lua_State *L)
{
	int args_n = lua_gettop(L);
	if (args_n != 1 || !lua_isstring(L, 1))
		luaL_error(L, "Usage: parser.open(log_filename)");

	const char *filename = luaL_checkstring(L, 1);

	FILE *f = fopen(filename, "r");
	if (f == NULL)
		luaL_error(L, "%s: failed to open file", filename);

	char filetype[32], version[32];
	if (fgets(filetype, sizeof(filetype), f) == NULL ||
	    fgets(version,  sizeof(version),  f) == NULL) {
		luaL_error(L, "%s: failed to read log file header", filename);
	}

	if (strcmp("0.12\n", version) != 0) {
		version[strlen(version) - 1] = '\0';
		luaL_error(L, "%s: unsupported file format version '%s'",
			   filename, version);
	}
	lbox_xlog_skip_header(L, f, filename);

	struct ffi_xlog_cursor *obj = (struct ffi_xlog_cursor *)calloc(1,
			sizeof(struct ffi_xlog_cursor));
	if (obj == NULL) {
		/* TODO: throw error */
	}
	/* Construct xlog object */
	obj->xlobject = lbox_initxlog(f, filename);
	/* Construct xlog cursor */
	obj->xlcobject = (struct xlog_cursor *)calloc(1,
			sizeof(struct xlog_cursor));
	obj->xlcobject->ignore_crc = true;
	if (obj->xlcobject == NULL) {
		/* TODO: throw error */
	}
	xlog_cursor_open(obj->xlcobject, obj->xlobject);

	/* push iteration function */
	lua_pushcclosure(L, &lbox_xlog_parser_iterate, 1);
	/* push log and set GC */
	lbox_pushffixlog(L, obj);
	lua_pushcfunction(L, lbox_xlog_parser_gc);
	luaL_setcdatagc(L, -2);
	/* push iterator position */
	lua_pushinteger(L, 0);
	return 3;
}

static const struct luaL_reg lbox_xlog_parser_lib [] = {
	{ "pairs",	lbox_xlog_parser_open_pairs },
	{ NULL,		NULL                        }
};

void
box_lua_xlog_parser_init(struct lua_State *L)
{
	int rc = 0;
	/* Get CTypeIDs */
	rc = luaL_cdef(L, "struct ffi_xlog_cursor;"); assert(rc == 0); (void) rc;
	CTID_STRUCT_FFI_XLOG_CURSOR_REF = luaL_ctypeid(L, "struct ffi_xlog_cursor&");
	assert(CTID_STRUCT_FFI_XLOG_CURSOR_REF != 0);

	luaL_register_module(L, xloglib_name, lbox_xlog_parser_lib);

	lua_newtable(L);
	lua_setmetatable(L, -2);
	lua_pop(L, 1);
}
