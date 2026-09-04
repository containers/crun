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
 * It is written against the public libcrun API (<libcrun.h>) only; it does
 * not access any internal struct field or ocispec type.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <lua.h>
#include <lauxlib.h>
#include <libcrun/libcrun.h>

static const char *LUA_CRUN_TAG_CTX = "crun-ctx";
static const char *LUA_CRUN_TAG_CONT = "crun-container";
static const char *LUA_CRUN_TAG_CONTS_ITER = "crun-containers-iterator";

#define luacrunL_optboolean(L, n, d) luaL_opt (S, lua_toboolean, n, d)

/* uservalue index of the context's field cache table. */
#define LUACRUN_CTX_CACHE_UV 1

// Soft error = return an error.
// When `expr` is false, run `onfailed` and push the string from `crun_err`.
// Return `addret + 1`.
#define luacrun_SoftErrIf(S, expr, crun_err, onfailed, addret) \
  if (expr)                                                    \
    {                                                          \
      onfailed;                                                \
      return luacrun_error (S, crun_err) + addret;             \
    }

extern int lua_error (lua_State *L);
extern int luaL_error (lua_State *L, const char *fmt, ...);

/* Build the error string, push onto stack. */
LUA_API int
luacrun_error (lua_State *S, libcrun_error_t *err)
{
  luaL_checkstack (S, 1, NULL);
  if (*err == NULL)
    {
      lua_pushstring (S, "the error is NULL, this may be a bug in luacrun");
      return 1;
    }
  int status = libcrun_error_get_status (*err);
  const char *msg = libcrun_error_get_message (*err);
  if (status == 0)
    {
      lua_pushfstring (S, "crun: %s", msg);
    }
  else
    {
      lua_pushfstring (S, "crun: %s(%s)", msg, strerror (status));
    }
  libcrun_error_release (err);
  return 1;
}

LUA_API void
luacrun_set_error (lua_State *S, libcrun_error_t *err)
{
  luacrun_error (S, err);
  lua_error (S);
}

/* Return the underlying context pointer, raising a Lua error if released. */
static libcrun_context_t *
luacrun_check_ctx (lua_State *S, int idx)
{
  libcrun_context_t **ctxp = luaL_checkudata (S, idx, LUA_CRUN_TAG_CTX);
  if (*ctxp == NULL)
    luaL_error (S, "the context is already released");
  return *ctxp;
}

/* Store cache[field] = value on top of the stack, for later reads by the
 * get accessors.  The value is left in place. [-0, +0] */
static void
luacrun_ctx_cache_set (lua_State *S, int ctx_idx, const char *field)
{
  luaL_checkstack (S, 2, NULL);
  lua_getiuservalue (S, ctx_idx, LUACRUN_CTX_CACHE_UV); /* +1 cache */
  lua_pushvalue (S, -2);                                /* +1 value copy */
  lua_setfield (S, -2, field);                          /* -1 */
  lua_pop (S, 1);                                       /* -1 cache */
}

/* Apply a string field from the table at tab_idx to the context using setter,
 * caching it for the get accessors. [-0, +0] */
static void
luacrun_ctx_apply_string (lua_State *S, int ctx_idx, int tab_idx, const char *field,
                          void (*setter) (libcrun_context_t *, const char *))
{
  int t = lua_getfield (S, tab_idx, field);
  if (t == LUA_TSTRING)
    {
      libcrun_context_t *ctx = *(libcrun_context_t **) lua_touserdata (S, ctx_idx);
      setter (ctx, lua_tostring (S, -1));
      luacrun_ctx_cache_set (S, ctx_idx, field);
    }
  else if (t != LUA_TNIL)
    {
      lua_pop (S, 1);
      luaL_error (S, "unknown type %s for field \"%s\"", lua_typename (S, t), field);
    }
  lua_pop (S, 1);
}

/* Apply a boolean field from the table at tab_idx to the context. [-0, +0] */
static void
luacrun_ctx_apply_bool (lua_State *S, int ctx_idx, int tab_idx, const char *field,
                        void (*setter) (libcrun_context_t *, bool))
{
  int t = lua_getfield (S, tab_idx, field);
  if (t == LUA_TBOOLEAN)
    {
      libcrun_context_t *ctx = *(libcrun_context_t **) lua_touserdata (S, ctx_idx);
      bool v = lua_toboolean (S, -1);
      setter (ctx, v);
      luacrun_ctx_cache_set (S, ctx_idx, field);
    }
  else if (t != LUA_TNIL)
    {
      lua_pop (S, 1);
      luaL_error (S, "unknown type %s for field \"%s\"", lua_typename (S, t), field);
    }
  lua_pop (S, 1);
}

/* Setup context by a table. The table is at tab_idx, the context userdata at
 * ctx_idx. [-0, +0] */
static void
luacrun_ctx_setup (lua_State *S, int ctx_idx, int tab_idx)
{
  luacrun_ctx_apply_string (S, ctx_idx, tab_idx, "state_root", libcrun_context_set_state_root);
  luacrun_ctx_apply_string (S, ctx_idx, tab_idx, "id", libcrun_context_set_id);
  luacrun_ctx_apply_string (S, ctx_idx, tab_idx, "bundle", libcrun_context_set_bundle);
  luacrun_ctx_apply_string (S, ctx_idx, tab_idx, "console_socket", libcrun_context_set_console_socket);
  luacrun_ctx_apply_string (S, ctx_idx, tab_idx, "pid_file", libcrun_context_set_pid_file);
  luacrun_ctx_apply_string (S, ctx_idx, tab_idx, "notify_socket", libcrun_context_set_notify_socket);
  luacrun_ctx_apply_string (S, ctx_idx, tab_idx, "handler", libcrun_context_set_handler);

  luacrun_ctx_apply_bool (S, ctx_idx, tab_idx, "systemd_cgroup", libcrun_context_set_systemd_cgroup);
  luacrun_ctx_apply_bool (S, ctx_idx, tab_idx, "detach", libcrun_context_set_detach);
}

/* Create a crun context. */
LUA_API int
luacrun_new_ctx (lua_State *S)
{
  if (! (lua_isnoneornil (S, 1) || lua_istable (S, 1)))
    luaL_argerror (S, 1, "expect table, nil or none");

  luaL_checkstack (S, 4, NULL);

  /* The constructor needs id and state_root up front; read them (keeping the
   * strings on the stack so they stay alive) before allocating. */
  const char *id = NULL;
  const char *state_root = NULL;
  int pushed = 0;
  if (lua_istable (S, 1))
    {
      if (lua_getfield (S, 1, "id") == LUA_TSTRING)
        {
          id = lua_tostring (S, -1);
          pushed++;
        }
      else
        lua_pop (S, 1);
      if (lua_getfield (S, 1, "state_root") == LUA_TSTRING)
        {
          state_root = lua_tostring (S, -1);
          pushed++;
        }
      else
        lua_pop (S, 1);
    }

  libcrun_error_t crun_err = NULL;
  libcrun_context_t *ctx = libcrun_context_new (id, state_root, &crun_err);
  lua_pop (S, pushed); /* the strings were copied by libcrun_context_new */
  if (ctx == NULL)
    {
      lua_pushnil (S);
      return luacrun_error (S, &crun_err) + 1;
    }

  libcrun_context_t **ctxp = lua_newuserdatauv (S, sizeof (*ctxp), 1);
  *ctxp = ctx;
  int ctx_idx = lua_gettop (S);
  lua_newtable (S);
  lua_setiuservalue (S, ctx_idx, LUACRUN_CTX_CACHE_UV);
  luaL_setmetatable (S, LUA_CRUN_TAG_CTX);

  if (lua_istable (S, 1))
    luacrun_ctx_setup (S, ctx_idx, 1);

  return 1;
}

/* Release the context. Double use is supported. */
LUA_API int
luacrun_ctx_finalizer (lua_State *S)
{
  libcrun_context_t **ctxp = luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);
  if (*ctxp != NULL)
    {
      libcrun_context_free (*ctxp);
      *ctxp = NULL;
    }
  return 0;
}

/*Grab a basic container spec.*/
LUA_API int
luacrun_container_spec (lua_State *S)
{
  bool rootless = luacrunL_optboolean (S, 1, true);
  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 1, NULL);
  char *json = NULL;
  int ret = libcrun_container_spec_json (rootless, &json, &crun_err);
  luacrun_SoftErrIf (S, ret < 0, &crun_err, lua_pushnil (S), 1);
  lua_pushstring (S, json);
  free (json);
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
      libcrun_container_free (*cont);
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
  libcrun_context_t *ctx = luacrun_check_ctx (S, 1);
  libcrun_container_t **cont = luaL_checkudata (S, 2, LUA_CRUN_TAG_CONT);
  unsigned int flags = luaL_opt (S, luacrun_build_run_flags, 3, 0);

  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 1, NULL);
  int ret = libcrun_container_run (ctx, *cont, flags, &crun_err);
  if (ret < 0)
    {
      if (crun_err != NULL)
        {
          lua_pushnil (S);
          return luacrun_error (S, &crun_err) + 1;
        }
      else
        {
          return luaL_error (S, "failed to run container");
        }
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
  libcrun_context_t *ctx = luacrun_check_ctx (S, 1);
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
  libcrun_context_t *ctx = luacrun_check_ctx (S, 1);
  const char *id = luaL_checkstring (S, 2);
  bool force = luaL_opt (S, lua_toboolean, 3, false);

  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 1, NULL);
  int ret = libcrun_container_delete (ctx, id, force, &crun_err);
  bool has_error = ret < 0 && crun_err != NULL;
  luacrun_SoftErrIf (S, has_error, &crun_err, lua_pushboolean (S, false), 1);
  lua_pushboolean (S, ret >= 0); // false if failed to read the exec.fifo in the state dir
  return 1;
}

LUA_API int
luacrun_ctx_kill_container (lua_State *S)
{
  libcrun_context_t *ctx = luacrun_check_ctx (S, 1);
  const char *id = luaL_checkstring (S, 2);
  const char *signame = luaL_checkstring (S, 3);

  libcrun_error_t crun_err = NULL;
  luaL_checkstack (S, 1, NULL);
  int ret = libcrun_container_kill (ctx, id, signame, &crun_err);
  luacrun_SoftErrIf (S, ret < 0, &crun_err, lua_pushboolean (S, false), 1);
  lua_pushboolean (S, true);
  return 1;
}

/* Map the container state enum to the canonical OCI status string. */
static const char *
luacrun_state_string (libcrun_container_state_t state)
{
  switch (state)
    {
    case LIBCRUN_CONTAINER_STATUS_CREATING:
      return "creating";
    case LIBCRUN_CONTAINER_STATUS_CREATED:
      return "created";
    case LIBCRUN_CONTAINER_STATUS_RUNNING:
      return "running";
    case LIBCRUN_CONTAINER_STATUS_PAUSED:
      return "paused";
    case LIBCRUN_CONTAINER_STATUS_STOPPED:
    default:
      return "stopped";
    }
}

/* Get the container status. (ctx: userdata, id: string) [-0, +1, -] */
LUA_API int
luacrun_ctx_status_container (lua_State *S)
{
  libcrun_context_t *ctx = luacrun_check_ctx (S, 1);
  const char *id = luaL_checkstring (S, 2);

  luaL_checkstack (S, 3, NULL);

  libcrun_error_t crun_err = NULL;
  libcrun_status_t *status = NULL;
  int ret = libcrun_container_status_load (ctx, id, &status, &crun_err);
  luacrun_SoftErrIf (S, ret < 0 && crun_err != NULL, &crun_err, lua_pushnil (S), 1);
  if (ret < 0)
    {
      lua_pushnil (S);
      lua_pushstring (S, "failed to read state");
      return 2;
    }

  lua_createtable (S, 0, 0);
  int tabidx = lua_gettop (S);

  lua_pushstring (S, "1.0.0");
  lua_setfield (S, tabidx, "ociVersion");
  lua_pushvalue (S, 2);
  lua_setfield (S, tabidx, "id");

  libcrun_container_state_t state = libcrun_status_get_state (status);
  bool running = state == LIBCRUN_CONTAINER_STATUS_RUNNING || state == LIBCRUN_CONTAINER_STATUS_PAUSED;

  lua_pushinteger (S, running ? libcrun_status_get_pid (status) : 0);
  lua_setfield (S, tabidx, "pid");

  struct luacrun_string_pair
  {
    const char *k;
    const char *v;
  };
  const struct luacrun_string_pair values[] = {
    { "status", luacrun_state_string (state) },
    { "bundle", libcrun_status_get_bundle (status) },
    { "rootfs", libcrun_status_get_rootfs (status) },
    { "created", libcrun_status_get_created (status) },
    { NULL, NULL },
  };
  for (int i = 0; values[i].k != NULL; i++)
    {
      if (values[i].v != NULL)
        {
          lua_pushstring (S, values[i].v);
          lua_setfield (S, tabidx, values[i].k);
        }
    }

  libcrun_container_status_free (status);
  return 1;
}

LUA_API int
luacrun_ctx_start_container (lua_State *S)
{
  libcrun_context_t *ctx = luacrun_check_ctx (S, 1);
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
  bool closed; // flag for if the list and cursor were freed
  libcrun_container_list_t *list;
  libcrun_container_iter_t *iter;
  lua_Integer counter;
};

static void
luacrun_ctx_containers_close (struct luacrun_ctx_containers_iterator *it)
{
  it->closed = true;
  libcrun_container_iter_free (it->iter);
  libcrun_container_list_free (it->list);
  it->iter = NULL;
  it->list = NULL;
}

static int
luacrun_ctx_containers_iteratorf (lua_State *S)
{
  // params: userdata integer
  const char *id = NULL;
  luaL_checktype (S, 1, LUA_TUSERDATA);
  struct luacrun_ctx_containers_iterator *it = lua_touserdata (S, 1);
  luaL_checkstack (S, 2, NULL);
  if (! it->closed && libcrun_container_iter_next (it->iter, &id))
    {
      lua_pushinteger (S, ++(it->counter));
      lua_pushstring (S, id);
      return 2;
    }
  else
    {
      luacrun_ctx_containers_close (it);
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
      luacrun_ctx_containers_close (iter);
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
  libcrun_context_t *ctx = luacrun_check_ctx (S, 1);

  luaL_checkstack (S, 4, NULL);
  lua_pushcfunction (S, &luacrun_ctx_containers_iteratorf);

  libcrun_container_list_t *containers = NULL;
  int ret = libcrun_container_list (ctx, &containers, &crun_err);
  if (ret < 0 && crun_err != NULL)
    luacrun_set_error (S, &crun_err);
  // ret < 0 && crun_err == NULL: the status file does not exist.
  // The `containers` is still NULL,
  // the iterator function knows how to handle the situation
  struct luacrun_ctx_containers_iterator *it = lua_newuserdata (S, sizeof (struct luacrun_ctx_containers_iterator));
  *it = (struct luacrun_ctx_containers_iterator){
    .closed = false,
    .counter = 0,
    .list = containers,
    .iter = libcrun_container_list_iter (containers),
  };

  luaL_setmetatable (S, LUA_CRUN_TAG_CONTS_ITER);
  lua_pushinteger (S, it->counter);
  lua_pushnil (S);
  return 4;
}

LUA_API int
luacrun_ctx_update_container (lua_State *S)
{
  libcrun_context_t *ctx = luacrun_check_ctx (S, 1);
  const char *id = luaL_checkstring (S, 2);
  const char *content = luaL_checkstring (S, 3);
  luaL_checkstack (S, 2, NULL);

  libcrun_error_t crun_err = NULL;
  int ret = libcrun_container_exec_json (ctx, id, content, &crun_err);
  if (ret < 0)
    {
      lua_pushboolean (S, false);
      if (crun_err != NULL)
        return luacrun_error (S, &crun_err) + 1;
      lua_pushstring (S, "failed to exec in container");
      return 2;
    }

  lua_pushboolean (S, true);
  return 1;
}

#define luacrun_CtxStringAccessor(name)                          \
  LUA_API int luacrun_ctx_get_##name (lua_State *S)              \
  {                                                              \
    luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);                    \
    luaL_checkstack (S, 2, NULL);                                \
    lua_getiuservalue (S, 1, LUACRUN_CTX_CACHE_UV);              \
    lua_getfield (S, -1, #name);                                 \
    return 1;                                                    \
  }                                                              \
  LUA_API int luacrun_ctx_set_##name (lua_State *S)              \
  {                                                              \
    libcrun_context_t *ctx = luacrun_check_ctx (S, 1);           \
    const char *val = luaL_optstring (S, 2, NULL);               \
    luaL_checkstack (S, 2, NULL);                                \
    libcrun_context_set_##name (ctx, val);                       \
    lua_getiuservalue (S, 1, LUACRUN_CTX_CACHE_UV);              \
    if (val != NULL)                                             \
      lua_pushstring (S, val);                                   \
    else                                                         \
      lua_pushnil (S);                                           \
    lua_setfield (S, -2, #name);                                 \
    return 0;                                                    \
  }

#define luacrun_CtxBoolAccessor(name)                            \
  LUA_API int luacrun_ctx_get_##name (lua_State *S)              \
  {                                                              \
    luaL_checkudata (S, 1, LUA_CRUN_TAG_CTX);                    \
    luaL_checkstack (S, 2, NULL);                                \
    lua_getiuservalue (S, 1, LUACRUN_CTX_CACHE_UV);              \
    if (lua_getfield (S, -1, #name) == LUA_TNIL)                 \
      {                                                          \
        lua_pop (S, 1);                                          \
        lua_pushboolean (S, 0);                                  \
      }                                                          \
    return 1;                                                    \
  }                                                              \
  LUA_API int luacrun_ctx_set_##name (lua_State *S)              \
  {                                                              \
    libcrun_context_t *ctx = luacrun_check_ctx (S, 1);           \
    luaL_checktype (S, 2, LUA_TBOOLEAN);                         \
    luaL_checkstack (S, 2, NULL);                                \
    bool v = lua_toboolean (S, 2);                               \
    libcrun_context_set_##name (ctx, v);                         \
    lua_getiuservalue (S, 1, LUACRUN_CTX_CACHE_UV);              \
    lua_pushboolean (S, v);                                      \
    lua_setfield (S, -2, #name);                                 \
    return 0;                                                    \
  }

luacrun_CtxStringAccessor (state_root);
luacrun_CtxStringAccessor (id);
luacrun_CtxStringAccessor (bundle);
luacrun_CtxStringAccessor (console_socket);
luacrun_CtxStringAccessor (pid_file);
luacrun_CtxStringAccessor (notify_socket);
luacrun_CtxStringAccessor (handler);

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
  lua_pushcfunction (S, &luacrun_ctx_finalizer);
  lua_setfield (S, mtab_idx, "__gc");
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
  lua_pushinteger (S, LIBCRUN_VERBOSITY_DEBUG);
  lua_setfield (S, libtab_idx, "VERBOSITY_DEBUG");

  luacrun_setup_ctx_metatable (S);
  luacrun_setup_cont_metatable (S);
  luacrun_setup_ctx_iter_metatable (S);
  return 1;
}
