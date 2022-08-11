/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020, 2021 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE

#include <config.h>
#include "../custom-handler.h"
#include "../container.h"
#include "../utils.h"
#include "../linux.h"
#include "handler-utils.h"
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_WASMTIME
#  include <wasm.h>
#  include <wasi.h>
#  include <wasmtime.h>
#endif

#if HAVE_DLOPEN && HAVE_WASMTIME
static int
libwasmtime_exec (void *cookie, libcrun_container_t *container,
                  const char *pathname, char *const argv[])
{
  size_t args_size = 0;
  char *const *arg;
  wasm_byte_vec_t error_message;
  wasm_engine_t *(*wasm_engine_new) ();
  void (*wasm_engine_delete) (wasm_engine_t *);
  void (*wasm_byte_vec_delete) (wasm_byte_vec_t *);
  void (*wasm_byte_vec_new_uninitialized) (wasm_byte_vec_t *, size_t);
  wasi_config_t *(*wasi_config_new) (const char *);
  wasmtime_store_t *(*wasmtime_store_new) (wasm_engine_t * engine, void *data, void (*finalizer) (void *));
  wasmtime_context_t *(*wasmtime_store_context) (wasmtime_store_t * store);
  wasmtime_linker_t *(*wasmtime_linker_new) (wasm_engine_t * engine);
  wasmtime_error_t *(*wasmtime_linker_define_wasi) (wasmtime_linker_t * linker);
  wasmtime_error_t *(*wasmtime_module_new) (
      wasm_engine_t * engine,
      const uint8_t *wasm,
      size_t wasm_len,
      wasmtime_module_t **ret);
  void (*wasi_config_inherit_argv) (wasi_config_t * config);
  void (*wasi_config_inherit_env) (wasi_config_t * config);
  void (*wasi_config_set_argv) (wasi_config_t * config, int argc, const char *argv[]);
  void (*wasi_config_inherit_stdin) (wasi_config_t * config);
  void (*wasi_config_inherit_stdout) (wasi_config_t * config);
  void (*wasi_config_inherit_stderr) (wasi_config_t * config);
  wasmtime_error_t *(*wasmtime_context_set_wasi) (wasmtime_context_t * context, wasi_config_t * wasi);
  wasmtime_error_t *(*wasmtime_linker_module) (
      wasmtime_linker_t * linker,
      wasmtime_context_t * store,
      const char *name,
      size_t name_len,
      const wasmtime_module_t *module);
  wasmtime_error_t *(*wasmtime_linker_get_default) (
      const wasmtime_linker_t *linker,
      wasmtime_context_t *store,
      const char *name,
      size_t name_len,
      wasmtime_func_t *func);
  wasmtime_error_t *(*wasmtime_func_call) (
      wasmtime_context_t * store,
      const wasmtime_func_t *func,
      const wasmtime_val_t *args,
      size_t nargs,
      wasmtime_val_t *results,
      size_t nresults,
      wasm_trap_t **trap);
  void (*wasmtime_module_delete) (wasmtime_module_t * m);
  void (*wasmtime_store_delete) (wasmtime_store_t * store);
  void (*wasmtime_error_message) (const wasmtime_error_t *error, wasm_name_t *message);
  void (*wasmtime_error_delete) (wasmtime_error_t * error);
  bool (*wasi_config_preopen_dir) (wasi_config_t * config, const char *path, const char *guest_path);

  wasm_engine_new = dlsym (cookie, "wasm_engine_new");
  wasm_engine_delete = dlsym (cookie, "wasm_engine_delete");
  wasm_byte_vec_delete = dlsym (cookie, "wasm_byte_vec_delete");
  wasm_byte_vec_new_uninitialized = dlsym (cookie, "wasm_byte_vec_new_uninitialized");
  wasi_config_new = dlsym (cookie, "wasi_config_new");
  wasi_config_set_argv = dlsym (cookie, "wasi_config_set_argv");
  wasmtime_store_new = dlsym (cookie, "wasmtime_store_new");
  wasmtime_store_context = dlsym (cookie, "wasmtime_store_context");
  wasmtime_linker_new = dlsym (cookie, "wasmtime_linker_new");
  wasmtime_linker_define_wasi = dlsym (cookie, "wasmtime_linker_define_wasi");
  wasmtime_module_new = dlsym (cookie, "wasmtime_module_new");
  wasi_config_inherit_argv = dlsym (cookie, "wasi_config_inherit_argv");
  wasi_config_inherit_stdout = dlsym (cookie, "wasi_config_inherit_stdout");
  wasi_config_inherit_stdin = dlsym (cookie, "wasi_config_inherit_stdin");
  wasi_config_inherit_stderr = dlsym (cookie, "wasi_config_inherit_stderr");
  wasi_config_inherit_env = dlsym (cookie, "wasi_config_inherit_env");
  wasmtime_context_set_wasi = dlsym (cookie, "wasmtime_context_set_wasi");
  wasmtime_linker_module = dlsym (cookie, "wasmtime_linker_module");
  wasmtime_linker_get_default = dlsym (cookie, "wasmtime_linker_get_default");
  wasmtime_func_call = dlsym (cookie, "wasmtime_func_call");
  wasmtime_module_delete = dlsym (cookie, "wasmtime_module_delete");
  wasmtime_store_delete = dlsym (cookie, "wasmtime_store_delete");
  wasmtime_error_delete = dlsym (cookie, "wasmtime_error_delete");
  wasmtime_error_message = dlsym (cookie, "wasmtime_error_message");
  wasi_config_preopen_dir = dlsym (cookie, "wasi_config_preopen_dir");

  if (wasm_engine_new == NULL || wasm_engine_delete == NULL || wasm_byte_vec_delete == NULL
      || wasm_byte_vec_new_uninitialized == NULL || wasi_config_new == NULL || wasmtime_store_new == NULL
      || wasmtime_store_context == NULL || wasmtime_linker_new == NULL || wasmtime_linker_define_wasi == NULL
      || wasmtime_module_new == NULL || wasi_config_inherit_argv == NULL || wasi_config_inherit_stdout == NULL
      || wasi_config_inherit_stdin == NULL || wasi_config_inherit_stderr == NULL
      || wasi_config_inherit_env == NULL || wasmtime_context_set_wasi == NULL
      || wasmtime_linker_module == NULL || wasmtime_linker_get_default == NULL || wasmtime_func_call == NULL
      || wasmtime_module_delete == NULL || wasmtime_store_delete == NULL || wasi_config_set_argv == NULL
      || wasmtime_error_delete == NULL || wasmtime_error_message == NULL || wasi_config_preopen_dir == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in `libwasmtime.so`");

  // Set up wasmtime context
  wasm_engine_t *engine = wasm_engine_new ();
  assert (engine != NULL);
  wasmtime_store_t *store = wasmtime_store_new (engine, NULL, NULL);
  assert (store != NULL);
  wasmtime_context_t *context = wasmtime_store_context (store);

  // Link with wasi functions defined
  wasmtime_linker_t *linker = wasmtime_linker_new (engine);
  wasmtime_error_t *err = wasmtime_linker_define_wasi (linker);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to link wasi: %s", error_message.data);
    }

  wasm_byte_vec_t wasm;
  // Load and parse container entrypoint
  FILE *file = fopen (pathname, "rb");
  if (! file)
    error (EXIT_FAILURE, 0, "error loading entrypoint");
  fseek (file, 0L, SEEK_END);
  size_t file_size = ftell (file);
  wasm_byte_vec_new_uninitialized (&wasm, file_size);
  fseek (file, 0L, SEEK_SET);
  if (fread (wasm.data, file_size, 1, file) != 1)
    error (EXIT_FAILURE, 0, "error load");
  fclose (file);

  // Compile wasm modules
  wasmtime_module_t *module = NULL;
  err = wasmtime_module_new (engine, (uint8_t *) wasm.data, wasm.size, &module);
  if (! module)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to compile module:%s", error_message.data);
    }
  wasm_byte_vec_delete (&wasm);

  // Init WASI program
  wasi_config_t *wasi_config = wasi_config_new ("crun_wasi_program");
  assert (wasi_config);

  // Calculate argc for `wasi_config_set_argv`
  for (arg = argv; *arg != NULL; ++arg)
    args_size++;

  wasi_config_set_argv (wasi_config, args_size, (const char **) argv);
  wasi_config_inherit_env (wasi_config);
  wasi_config_inherit_stdin (wasi_config);
  wasi_config_inherit_stdout (wasi_config);
  wasi_config_inherit_stderr (wasi_config);
  wasi_config_preopen_dir (wasi_config, ".", ".");
  wasm_trap_t *trap = NULL;
  err = wasmtime_context_set_wasi (context, wasi_config);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to instantiate WASI: %s", error_message.data);
    }

  // Init module
  err = wasmtime_linker_module (linker, context, "", 0, module);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to instantiate module: %s", error_message.data);
    }

  // Actually run our .wasm
  wasmtime_func_t func;
  err = wasmtime_linker_get_default (linker, context, "", 0, &func);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to locate default export for module %s", error_message.data);
    }

  err = wasmtime_func_call (context, &func, NULL, 0, NULL, 0, &trap);
  if (err != NULL || trap != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "error calling default export: %s", error_message.data);
    }

  // Clean everything
  wasmtime_module_delete (module);
  wasmtime_store_delete (store);
  wasm_engine_delete (engine);

  exit (EXIT_SUCCESS);
}

static int
libwasmtime_load (void **cookie, libcrun_error_t *err arg_unused)
{
  void *handle;

  handle = dlopen ("libwasmtime.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libwasmtime.so`: %s", dlerror ());
  *cookie = handle;

  return 0;
}

static int
libwasmtime_unload (void *cookie, libcrun_error_t *err arg_unused)
{
  int r;

  if (cookie)
    {
      r = dlclose (cookie);
      if (UNLIKELY (r < 0))
        return crun_make_error (err, 0, "could not unload handle: %s", dlerror ());
    }
  return 0;
}

static int
libwasmtime_can_handle_container (libcrun_container_t *container, libcrun_error_t *err arg_unused)
{
  return wasm_can_handle_container (container, err);
}

struct custom_handler_s handler_wasmtime = {
  .name = "wasmtime",
  .feature_string = "WASM:wasmtime",
  .load = libwasmtime_load,
  .unload = libwasmtime_unload,
  .exec_func = libwasmtime_exec,
  .can_handle_container = libwasmtime_can_handle_container,
};

#endif
