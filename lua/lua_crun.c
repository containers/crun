/*
 *crun - OCI runtime written in C
 *
 *Copyright (C) Rubicon Rowe <l1589002388@gmail.com>
 *crun is free software; you can redistribute it and/or modify
 *it under the terms of the GNU Lesser General Public License as published by
 *the Free Software Foundation; either version 2.1 of the License, or
 *(at your option) any later version.
 *
 *crun is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU Lesser General Public License for more details.
 *
 *You should have received a copy of the GNU Lesser General Public License
 *along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

/* This library is a bare libcrun interface and can be further wrapped by other libraries.
 *
 * There are some problems still and the API is a subject to change.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <lua.h>
#include <lauxlib.h>
#include <libcrun/container.h>
#include <libcrun/status.h>
#include <libcrun/utils.h>
#include <libcrun/error.h>

static const char *LUA_CRUN_TAG_CTX = "crun-ctx";
static const char *LUA_CRUN_TAG_CONT = "crun-container";
static const char *LUA_CRUN_TAG_CONTS_ITER = "crun-containers-iterator";

#define luacrunL_optboolean(L, n, d) luaL_opt (S, lua_toboolean, n, d)

// Soft error = return an error.
// When `expr` is false, run `onfailed` and push the string from `crun_err`.
// Return `addret + 1`.
#define luacrun_SoftErrIf(S, expr, crun_err, onfailed, addret) \
  if (expr)                                                    \
    {                                                          \
      onfailed;                                                \
      return luacrun_error (S, crun_err) + addret;             \
    }

#if __STDC_VERSION__ < 201112L
#  define LUACRUN_NoRet
#elif __STDC_VERSION__ < 202300L
#  define LUACRUN_NoRet _Noreturn
#else
#  define LUACRUN_NoRet [[noreturn]]
#endif

extern LUACRUN_NoRet int lua_error (lua_State *L);
extern LUACRUN_NoRet int luaL_error (lua_State *L, const char *fmt, ...);

/* Build the error string, push onto stack. */
LUA_API int
luacrun_error (lua_State *S, libcrun_error_t *err)
{
  luaL_checkstack (S, 1, NULL);
  if ((*err)->status == 0)
    {
      lua_pushfstring (S, "crun: %s", (*err)->msg);
    }
  else
    {
      lua_pushfstring (S, "crun: %s(%s)", (*err)->msg, strerror ((*err)->status));
    }
  libcrun_error_release (err);
  return 1;
}

LUA_API LUACRUN_NoRet void
luacrun_set_error (lua_State *S, libcrun_error_t *err)
{
  luacrun_error (S, err);
  lua_error (S);
}

/* This is a custom version of `xstrdup`(in src/libcrun/utils.h), return a Lua userdata.
 * Push the userdata onto stack, or nil if `s` is `NULL`.
 * This function does not check stack.
 * -0, +1, -
 */
static char *
luacrun_xstrdup (lua_State *S, const char *s)
{
  if (s != NULL)
    {
      size_t size = strlen (s) + 1;
      char *ret = lua_newuserdata (S, size);
      /* `lua_newuserdatauv` always returns a valid address,
      no need to check if the allocation is success */
      memcpy (ret, s, size);
      return ret;
    }
  else
    {
      lua_pushnil (S);
      return NULL;
    }
}

struct luacrun_args_holder
{
  const char **argv;
  int argc;
};

/* uservalues used by the ctx, the index + 1 is the uservalue idx.
the definition here is not stable. */
const char *luacrun_ctx_uservalues[] = {
  "state_root",
  "id",
  "bundle",
  "console_socket",
  "pid_file",
  "notify_socket",
  "handler",
  "args", // argv and argc
};

#define luacrun_CtxSetupStringField(S, ret, ctxidx, tabidx, field_name, name, uvalidx)       \
  ret = lua_getfield (S, tabidx, field_name);                                                \
  if (ret == LUA_TSTRING)                                                                    \
    {                                                                                        \
      ctx->name = luacrun_xstrdup (S, lua_tostring (S, -1));                                 \
    }                                                                                        \
  else if (ret == LUA_TNIL)                                                                  \
    {                                                                                        \
      lua_pushnil (S);                                                                       \
      ctx->name = NULL;                                                                      \
    }                                                                                        \
  else                                                                                       \
    {                                                                                        \
      lua_pop (S, 1);                                                                        \
      luaL_error (S, "unknown type %s for field \"%s\"", lua_typename (S, ret), field_name); \
    }                                                                                        \
  lua_setiuservalue (S, ctxidx, uvalidx);                                                    \
  lua_pop (S, 1)

#define luacrun_CtxSetupBoolField(S, ret, ctxidx, tabidx, field_name, name)                  \
  ret = lua_getfield (S, tab_idx, field_name);                                               \
  if (ret == LUA_TBOOLEAN)                                                                   \
    {                                                                                        \
      ctx->name = lua_toboolean (S, -1);                                                     \
    }                                                                                        \
  else if (ret != LUA_TNIL)                                                                  \
    {                                                                                        \
      lua_pop (S, 1);                                                                        \
      luaL_error (S, "unknown type %s for field \"%s\"", lua_typename (S, ret), field_name); \
    }                                                                                        \
  lua_pop (S, 1)

/* Setup context_t by a table. The table must be the stack top. [-0, +0] */
static void
luacrun_ctx_setup (lua_State *S, int ctxidx, int tab_idx)
{
  libcrun_context_t *ctx = lua_touserdata (S, ctxidx);

  int ret;

  luacrun_CtxSetupStringField (S, ret, ctxidx, tab_idx, "state_root", state_root, 1);
  luacrun_CtxSetupStringField (S, ret, ctxidx, tab_idx, "id", id, 2);
  luacrun_CtxSetupStringField (S, ret, ctxidx, tab_idx, "bundle", bundle, 3);
  luacrun_CtxSetupStringField (S, ret, ctxidx, tab_idx, "console_socket", console_socket, 4);
  luacrun_CtxSetupStringField (S, ret, ctxidx, tab_idx, "pid_file", pid_file, 5);
  luacrun_CtxSetupStringField (S, ret, ctxidx, tab_idx, "notify_socket", notify_socket, 6);
  luacrun_CtxSetupStringField (S, ret, ctxidx, tab_idx, "handler", handler, 7);

  luacrun_CtxSetupBoolField (S, ret, ctxidx, tabidx, "systemd_cgroup", systemd_cgroup);
  luacrun_CtxSetupBoolField (S, ret, ctxidx, tabidx, "detach", detach);

  ret = lua_getfield (S, tab_idx, "args");
  if (ret == LUA_TTABLE)
    {
      lua_Integer length = luaL_len (S, -1);
      if (length < 0 || length > (INT_MAX - 1))
        { /* A userdata can have INT_MAX uservalues */
          luaL_error (S, "field \"args\": length should be <= %d and > 0", INT_MAX - 1);
        }
      int argc = (int) length;
      const char **argv = lua_newuserdatauv (S, sizeof (char *) * argc, argc);
      int argv_idx = lua_gettop (S);
      for (int i = argc; i > 0; i--)
        {
          lua_geti (S, tab_idx, i);
          const char *arg = luaL_tolstring (S, -1, NULL);
          if (arg != NULL)
            {
              const char *copy = luacrun_xstrdup (S, arg);
              argv[i] = copy;
              lua_setiuservalue (S, argv_idx, i);
              lua_pop (S, 2); /* pop arg and result from lua_geti */
            }
          else
            {
              luaL_error (S, "field \"args\": failed to convert value (index %d) to string", i);
            }
        }
      /* Stack top: argv */

      struct luacrun_args_holder *args = lua_newuserdatauv (S, sizeof (struct luacrun_args_holder), 1);
      int args_idx = lua_gettop (S);
      args->argc = argc;
      args->argv = argv;
      lua_pushvalue (S, argv_idx);
      lua_setiuservalue (S, args_idx, 1);
      /* Stack top: args */
      lua_setiuservalue (S, ctxidx, 8); /* -1 */
      lua_pop (S, 1);
    }
  else if (ret != LUA_TNIL)
    {
      lua_pop (S, 1);
      luaL_error (S, "unknown type %s for field \"%s\"", lua_typename (S, ret), "args");
    }
  lua_pop (S, 1);
}

/* Create a crun context.
 */
LUA_API int
luacrun_new_ctx (lua_State *S)
{
  if (! (lua_isnil (S, 1) || lua_istable (S, 1)))
    {
      luaL_typeerror (S, 1, "table or nil");
    }

  luaL_checkstack (S, 1, NULL);
  /* Lua does not guarantee that string addresses will be valid for the lifetime of libcrun_context_t,
   * but we must respect the memory management function set by the user in lua_State.
   * (For the string memory guarantees: https://www.lua.org/manual/5.4/manual.html#4.1.3)
   *
   *   - Use userdata as string to ensure it will not be moved.
   *     ("Lua ensures that this address is valid as long as the corresponding userdata is alive":
   *       https://www.lua.org/manual/5.4/manual.html#lua_newuserdatauv)
   *   - Use uservalue to prevent being collected by GC.
   *
   */
  libcrun_context_t *ctx = lua_newuserdatauv (S, sizeof (libcrun_context_t), 8);
  int ctx_idx = lua_gettop (S);
  memset (ctx, 0, sizeof (libcrun_context_t));
  ctx->fifo_exec_wait_fd = -1;
  if (lua_istable (S, 1))
    {
      luacrun_ctx_setup (S, ctx_idx, 1);
    }
  luaL_setmetatable (S, LUA_CRUN_TAG_CTX);
  return 1;
}

/*Grab a basic container spec.*/
LUA_API int
luacrun_container_spec (lua_State *S)
{
  bool rootless = luacrunL_optboolean (S, 1, true);
  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 1, NULL);
  char buf[4096] = {};
  FILE *memfile = fmemopen (buf, 4095, "w");
  int ret = libcrun_container_spec (rootless, memfile, &crun_err); // the crun_err is not used
  fclose (memfile);
  luacrun_SoftErrIf (S, ret < 0, &crun_err, lua_pushnil (S), 1);
  lua_pushlstring (S, buf, ret);
  return 1;
}

LUA_API int
luacrun_new_container_from_string (lua_State *S)
{
  libcrun_error_t crun_err = NULL;
  const char *def = luaL_checkstring (S, 1);
  libcrun_container_t **cont = lua_newuserdata (S, sizeof (libcrun_container_t *));
  luaL_setmetatable (S, LUA_CRUN_TAG_CONT);
  *cont = libcrun_container_load_from_memory (def, &crun_err);
  if (*cont == NULL)
    {
      lua_pushnil (S);
      return luacrun_error (S, &crun_err) + 1;
    }
  return 1;
}

LUA_API int
luacrun_new_container_from_file (lua_State *S)
{
  libcrun_error_t crun_err = NULL;
  const char *path = luaL_checkstring (S, 1);
  libcrun_container_t **cont = lua_newuserdata (S, sizeof (libcrun_container_t *));
  luaL_setmetatable (S, LUA_CRUN_TAG_CONT);
  // create the userdata before calling crun, so we don't need to clean up when Lua failed
  *cont = libcrun_container_load_from_file (path, &crun_err);
  if (*cont == NULL)
    {
      lua_pushnil (S);
      return luacrun_error (S, &crun_err) + 1;
    }
  return 1;
}

/*Release resource linked with container userdata. Double use is supported.*/
LUA_API int
luacrun_container_finalizer (lua_State *S)
{
  libcrun_container_t **cont = luaL_checkudata (S, 1, LUA_CRUN_TAG_CONT);
  if (*cont != NULL)
    {
      free_runtime_spec_schema_config_schema ((*cont)->container_def);
      *cont = NULL;
    }
  return 0;
}

LUA_API int
luacrun_set_verbosity (lua_State *S)
{
  lua_Integer verbosity = luaL_checkinteger (S, 1);
  if (verbosity >= INT_MIN && verbosity <= INT_MAX)
    {
      libcrun_set_verbosity (verbosity);
    }
  else
    {
      luaL_error (S, "verbosity should be >= %d and <= %d", INT_MIN, INT_MAX);
    }
  return 0;
}

LUA_API int
luacrun_get_verbosity (lua_State *S)
{
  int verbosity = libcrun_get_verbosity ();
  lua_pushinteger (S, verbosity);
  return 1;
}

static unsigned int
luacrun_build_run_flags (lua_State *S, int idx)
{
  luaL_checktype (S, idx, LUA_TTABLE);
  lua_getfield (S, idx, "prefork");
  bool prefork = lua_toboolean (S, -1);
  lua_pop (S, 1);
  return (prefork ? LIBCRUN_RUN_OPTIONS_PREFORK : 0) | 0;
}

LUA_API int
luacrun_ctx_run (lua_State *S)
{
  libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);
  libcrun_container_t **cont = luaL_checkudata (S, 2, LUA_CRUN_TAG_CONT);
  unsigned int flags = luaL_opt (S, luacrun_build_run_flags, 3, 0);

  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 1, NULL);
  int ret = libcrun_container_run (ctx, *cont, flags, &crun_err);
  if (ret < 0)
    {
      lua_pushnil (S);
      return luacrun_error (S, &crun_err) + 1;
    }
  else
    {
      lua_pushinteger (S, ret);
      return 1;
    }
}

LUA_API int
luacrun_ctx_create_container (lua_State *S)
{
  libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);
  libcrun_container_t **cont = luaL_checkudata (S, 2, LUA_CRUN_TAG_CONT);
  unsigned int flags = luaL_opt (S, luacrun_build_run_flags, 3, LIBCRUN_RUN_OPTIONS_PREFORK);

  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 1, NULL);
  int ret = libcrun_container_create (ctx, *cont, flags, &crun_err);
  if (ret < 0)
    {
      lua_pushnil (S);
      return luacrun_error (S, &crun_err) + 1;
    }
  else
    {
      lua_pushinteger (S, ret);
      return 1;
    }
}

LUA_API int
luacrun_ctx_delete_container (lua_State *S)
{
  libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);
  const char *id = luaL_checkstring (S, 2);
  bool force = luaL_opt (S, lua_toboolean, 3, false);

  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 1, NULL);
  int ret = libcrun_container_delete (ctx, NULL, id, force, &crun_err);
  luacrun_SoftErrIf (S, ret < 0, &crun_err, lua_pushboolean (S, false), 1);
  lua_pushboolean (S, true);
  return 1;
}

LUA_API int
luacrun_ctx_kill_container (lua_State *S)
{
  libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);
  const char *id = luaL_checkstring (S, 2);
  const char *signame = luaL_checkstring (S, 3);

  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 1, NULL);
  int ret = libcrun_container_kill (ctx, id, signame, &crun_err);
  luacrun_SoftErrIf (S, ret < 0, &crun_err, lua_pushboolean (S, false), 1);
  lua_pushboolean (S, true);
  return 1;
}

/* Get the container status. (ctx: userdata, id: string) [-0, +1, -]

This function is a rewrite of `libcrun_container_state` for Lua.
`libcrun_container_state` receives `FILE*` and writes JSON.
We could not use `fmemopen` like `luacrun_container_spec` since the final size of
the string is 100% unpredictable.
*/
LUA_API int
luacrun_ctx_status_container (lua_State *S)
{
  libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);
  const char *id = luaL_checkstring (S, 2);

  luaL_checkstack (S, 3, NULL);

  libcrun_error_t crun_err = NULL;
  int ret;
  lua_createtable (S, 0, 0);
  int tabidx = lua_gettop (S);

  // We know there are two frames available on the stack from this point.

  lua_pushstring (S, "1.0.0");
  lua_setfield (S, tabidx, "ociVersion");
  lua_pushvalue (S, 2);
  lua_setfield (S, tabidx, "id");

  libcrun_container_status_t status = {};
  const char *state_root = ctx->state_root;
  ret = libcrun_read_container_status (&status, state_root, id, &crun_err);
  luacrun_SoftErrIf (S, ret < 0, &crun_err, lua_pushnil (S), 1);

  const char *container_status = NULL;
  int running;
  ret = libcrun_get_container_state_string (id, &status, state_root, &container_status, &running, &crun_err);
  luacrun_SoftErrIf (S, ret < 0, &crun_err, lua_pushnil (S), 1);

  lua_pushinteger (S, running ? status.pid : 0);
  lua_setfield (S, tabidx, "pid");
  struct luacrun_string_pair
  {
    const char *k;
    const char *v;
  };
  const struct luacrun_string_pair values[] = {
    { "status", container_status },
    { "bundle", status.bundle },
    { "rootfs", status.rootfs },
    { "created", status.created },
    { "systemd-scope", status.scope }, /* maybe NULL*/
    { "owner", status.owner },         /* maybe NULL */
    { NULL, NULL },
  };
  for (int i = 0; values[i].k != NULL; i++)
    {
      const struct luacrun_string_pair p = values[i];
      if (p.v != NULL)
        {
          lua_pushstring (S, p.v);
          lua_setfield (S, tabidx, p.k);
        }
    }

  {
    cleanup_container libcrun_container_t *container = NULL;
    cleanup_free char *dir = NULL;

    dir = libcrun_get_state_directory (state_root, id);
    if (dir == NULL)
      {
        lua_pushnil (S);
        lua_pushstring (S, "cannot get state directory");
        return 2;
      }

    const char *config_file = lua_pushfstring (S, "%s/%s", dir, "config.json");

    container = libcrun_container_load_from_file (config_file, &crun_err);
    lua_pop (S, 1);
    if (container == NULL)
      {
        lua_pushnil (S);
        lua_pushstring (S, "error loading config.json");
        return 2;
      }

    if (container->container_def->annotations && container->container_def->annotations->len)
      {
        /* Check stack again, we need three available frames here. */
        luaL_checkstack (S, 3, NULL);
        lua_createtable (S, 0, container->container_def->annotations->len);
        for (size_t i = 0; i < container->container_def->annotations->len; i++)
          {
            const char *key = container->container_def->annotations->keys[i];
            const char *val = container->container_def->annotations->values[i];
            lua_pushstring (S, val);
            lua_setfield (S, tabidx, key);
          }
        lua_setfield (S, tabidx, "annotations");
      }
  }
  return 1;
}

LUA_API int
luacrun_ctx_start_container (lua_State *S)
{
  libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);
  const char *id = luaL_checkstring (S, 2);

  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 2, NULL);
  int ret = libcrun_container_start (ctx, id, &crun_err);
  luacrun_SoftErrIf (S, ret < 0, &crun_err, lua_pushboolean (S, false), 1);
  lua_pushboolean (S, true);
  return 1;
}

struct luacrun_ctx_containers_iterator
{
  bool closed; // flag for if the libcrun_container_list_t free'd
  libcrun_container_list_t *start;
  libcrun_container_list_t *curr;
  lua_Integer counter;
};

static int
luacrun_ctx_containers_iteratorf (lua_State *S)
{
  // params: userdata integer
  luaL_checktype (S, 1, LUA_TUSERDATA);
  struct luacrun_ctx_containers_iterator *it = lua_touserdata (S, 1);
  luaL_checkstack (S, 2, NULL);
  if (it->curr != NULL)
    {
      lua_pushinteger (S, ++(it->counter));
      lua_pushstring (S, it->curr->name);
      it->curr = it->curr->next;
      return 2;
    }
  else
    {
      it->closed = true;
      libcrun_free_containers_list (it->start);
      lua_pushnil (S);
      return 1;
    }
}

static int
luacrun_ctx_containers_finalizer (lua_State *S)
{
  luaL_checktype (S, 1, LUA_TUSERDATA);
  struct luacrun_ctx_containers_iterator *iter = lua_touserdata (S, 1);
  if (! iter->closed)
    {
      libcrun_free_containers_list (iter->start);
    }
  return 0;
}

static const luaL_Reg luacrun_ctx_containers_iterator_metamethods[] = {
  { "__gc", &luacrun_ctx_containers_finalizer },
  { NULL, NULL },
};

static int
luacrun_setup_ctx_iter_metatable (lua_State *S)
{
  luaL_newmetatable (S, LUA_CRUN_TAG_CONTS_ITER);
  luaL_setfuncs (S, luacrun_ctx_containers_iterator_metamethods, 0);
  lua_pop (S, 1);
  return 0;
}

LUA_API int
luacrun_ctx_iter_containers (lua_State *S)
{
  libcrun_error_t crun_err = NULL;
  libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);

  luaL_checkstack (S, 4, NULL);
  lua_pushcfunction (S, &luacrun_ctx_containers_iteratorf);

  libcrun_container_list_t *containers;
  int ret = libcrun_get_containers_list (&containers, ctx->state_root, &crun_err);
  if (ret < 0)
    luacrun_set_error (S, &crun_err);
  struct luacrun_ctx_containers_iterator *it = lua_newuserdata (S, sizeof (struct luacrun_ctx_containers_iterator));
  *it = (struct luacrun_ctx_containers_iterator){
    .closed = false,
    .counter = 0,
    .curr = containers,
    .start = containers,
  };

  luaL_setmetatable (S, LUA_CRUN_TAG_CONTS_ITER);
  lua_pushinteger (S, it->counter);
  lua_pushnil (S);
  return 4;
}

LUA_API int
luacrun_ctx_update_container (lua_State *S)
{
  libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);
  const char *id = luaL_checkstring (S, 2);
  const char *content = luaL_checkstring (S, 3);
  luaL_checkstack (S, 2, NULL);

  char errbuf[1024] = {};
  yajl_val parsed_json = yajl_tree_parse (content, errbuf, sizeof (errbuf));
  if (parsed_json == NULL)
    {
      lua_pushboolean (S, false);
      lua_pushfstring (S, "cannot parse the data: \"%s\"", errbuf);
      return 2;
    }

  struct parser_context parser_ctx = { .options = 0, .errfile = stderr };
  runtime_spec_schema_config_schema_process *rt_spec_process;
  parser_error p_err = NULL;
  rt_spec_process = make_runtime_spec_schema_config_schema_process (parsed_json, &parser_ctx, &p_err);
  yajl_tree_free (parsed_json);
  if (rt_spec_process == NULL)
    {
      lua_pushboolean (S, false);
      lua_pushfstring (S, "cannot parse process: \"%s\"", p_err);
      free (p_err);
      return 2;
    }

  libcrun_error_t crun_err = NULL;
  int ret = libcrun_container_exec (ctx, id, rt_spec_process, &crun_err);
  free_runtime_spec_schema_config_schema_process (rt_spec_process);
  luacrun_SoftErrIf (S, ret < 0, &crun_err, lua_pushboolean (S, false), 1);

  lua_pushboolean (S, true);
  return 1;
}

#define luacrun_CtxStringAccessor(name, uval_idx)                      \
  LUA_API int luacrun_ctx_get_##name (lua_State *S)                    \
  {                                                                    \
    libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX); \
    if (ctx->name != NULL)                                             \
      {                                                                \
        luaL_checkstack (S, 1, NULL);                                  \
        lua_pushstring (S, ctx->name);                                 \
        return 1;                                                      \
      }                                                                \
    else                                                               \
      {                                                                \
        return 0;                                                      \
      }                                                                \
  }                                                                    \
  LUA_API int luacrun_ctx_set_##name (lua_State *S)                    \
  {                                                                    \
    libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX); \
    const char *val = luaL_optstring (S, 2, NULL);                     \
    luaL_checkstack (S, 2, NULL);                                      \
    if (ctx->name != NULL)                                             \
      {                                                                \
        lua_pushstring (S, ctx->name);                                 \
      }                                                                \
    else                                                               \
      {                                                                \
        lua_pushnil (S);                                               \
      }                                                                \
    const char *copy = luacrun_xstrdup (S, val);                       \
    ctx->name = copy;                                                  \
    lua_setiuservalue (S, 1, uval_idx);                                \
    return 1;                                                          \
  }

#define luacrun_CtxBoolAccessor(name)                                  \
  LUA_API int luacrun_ctx_get_##name (lua_State *S)                    \
  {                                                                    \
    libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX); \
    luaL_checkstack (S, 1, NULL);                                      \
    lua_pushboolean (S, ctx->name);                                    \
    return 1;                                                          \
  }                                                                    \
  LUA_API int luacrun_ctx_set_##name (lua_State *S)                    \
  {                                                                    \
    libcrun_context_t *ctx = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX); \
    luaL_checktype (S, 2, LUA_TBOOLEAN);                               \
    luaL_checkstack (S, 1, NULL);                                      \
    bool oldval = ctx->name;                                           \
    ctx->name = lua_toboolean (S, 2);                                  \
    lua_pushboolean (S, oldval);                                       \
    return 1;                                                          \
  }

luacrun_CtxStringAccessor (state_root, 1);
luacrun_CtxStringAccessor (id, 2);
luacrun_CtxStringAccessor (bundle, 3);
luacrun_CtxStringAccessor (console_socket, 4);
luacrun_CtxStringAccessor (pid_file, 5);
luacrun_CtxStringAccessor (notify_socket, 6);
luacrun_CtxStringAccessor (handler, 7);

luacrun_CtxBoolAccessor (systemd_cgroup);

#define luacrun_RegAddCtxAccessor(method_name, name) \
  { method_name, &luacrun_ctx_get_##name },          \
  {                                                  \
    "set_" method_name, &luacrun_ctx_set_##name      \
  }

static const luaL_Reg luacrun_ctx_index[]
    = {
        { "run", &luacrun_ctx_run },
        { "create", &luacrun_ctx_create_container },
        { "delete", &luacrun_ctx_delete_container },
        { "kill", &luacrun_ctx_kill_container },
        { "start", &luacrun_ctx_start_container },
        { "status", &luacrun_ctx_status_container },
        { "iter_names", &luacrun_ctx_iter_containers },
        { "update", &luacrun_ctx_update_container },
        luacrun_RegAddCtxAccessor ("state_root", state_root),
        luacrun_RegAddCtxAccessor ("id", id),
        luacrun_RegAddCtxAccessor ("bundle", bundle),
        luacrun_RegAddCtxAccessor ("console_socket", console_socket),
        luacrun_RegAddCtxAccessor ("pid_file", pid_file),
        luacrun_RegAddCtxAccessor ("notify_socket", notify_socket),
        luacrun_RegAddCtxAccessor ("handler", handler),
        luacrun_RegAddCtxAccessor ("systemd_cgroup", systemd_cgroup),
        { NULL, NULL },
      };

LUA_API int
luacrun_setup_ctx_metatable (lua_State *S)
{
  luaL_checkstack (S, 3, NULL);
  luaL_newmetatable (S, LUA_CRUN_TAG_CTX);
  int mtab_idx = lua_gettop (S);
  lua_newtable (S);
  luaL_setfuncs (S, luacrun_ctx_index, 0);
  lua_setfield (S, mtab_idx, "__index");
  lua_pop (S, 1);
  return 0;
}

LUA_API int
luacrun_setup_cont_metatable (lua_State *S)
{
  luaL_checkstack (S, 2, NULL);
  luaL_newmetatable (S, LUA_CRUN_TAG_CONT);
  int mtab_idx = lua_gettop (S);
  lua_pushcfunction (S, &luacrun_container_finalizer);
  lua_setfield (S, mtab_idx, "__gc");
  // Can we do better than a finalizer?
  // Indirect pointer and wild memory make
  // Lua GC could not recognize the memory usage.
  lua_pop (S, 1);
  return 0;
}

static const luaL_Reg luacrun_library_reg[] = {
  { .name = "new_ctx", .func = &luacrun_new_ctx },
  { .name = "container_spec", .func = &luacrun_container_spec },
  { .name = "new_container_from_string", .func = &luacrun_new_container_from_string },
  { .name = "new_container_from_file", .func = &luacrun_new_container_from_file },
  { .name = "get_verbosity", .func = &luacrun_get_verbosity },
  { .name = "set_verbosity", .func = &luacrun_set_verbosity },
  { .name = "run", .func = &luacrun_ctx_run },
  { .name = "create_container", .func = &luacrun_ctx_create_container },
  { .name = "delete_container", .func = &luacrun_ctx_delete_container },
  { .name = "kill_container", .func = &luacrun_ctx_kill_container },
  { .name = "start_container", .func = &luacrun_ctx_start_container },
  { .name = "status_container", .func = &luacrun_ctx_status_container },
  { .name = "iter_container_names", .func = &luacrun_ctx_iter_containers },
  { .name = "update_container", .func = &luacrun_ctx_update_container },
  { NULL, NULL },
};

LUA_API int
luaopen_luacrun (lua_State *S)
{
  luaL_checkstack (S, 2, NULL);
  luaL_newlib (S, luacrun_library_reg);
  int libtab_idx = lua_gettop (S);

  lua_pushinteger (S, LIBCRUN_VERBOSITY_ERROR);
  lua_setfield (S, libtab_idx, "VERBOSITY_ERROR");
  lua_pushinteger (S, LIBCRUN_VERBOSITY_WARNING);
  lua_setfield (S, libtab_idx, "VERBOSITY_WARNING");

  luacrun_setup_ctx_metatable (S);
  luacrun_setup_cont_metatable (S);
  luacrun_setup_ctx_iter_metatable (S);
  return 1;
}
