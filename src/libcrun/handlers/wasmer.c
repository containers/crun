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

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_WASMER
#  include <wasmer.h>
#endif

#if HAVE_DLOPEN && HAVE_WASMER
#  define WASMER_BUF_SIZE 128
static int
libwasmer_exec (void *cookie, libcrun_container_t *container,
                const char *pathname, char *const argv[])
{
  int ret;
  char buffer[WASMER_BUF_SIZE] = { 0 };
  size_t data_read_size = WASMER_BUF_SIZE;
  const wasm_func_t *core_func;
  FILE *wat_wasm_file;
  size_t file_size;
  wasm_byte_vec_t wat;
  wasm_byte_vec_t binary_bytes;
  wasm_byte_vec_t wasm_bytes;
  wasm_engine_t *engine;
  wasm_val_t results_val[1] = { WASM_INIT_VAL };
  wasm_store_t *store;
  wasm_module_t *module;
  wasm_instance_t *instance;
  wasm_extern_vec_t exports;
  size_t args_size = 0;
  cleanup_free char *wasi_args = NULL;
  wasi_config_t *config;
  char *const *arg;
  wasi_env_t *wasi_env;
  wasm_importtype_vec_t import_types;
  wasm_extern_vec_t imports;
  wasm_func_t *run_func;
  wasm_val_vec_t args = WASM_EMPTY_VEC;
  wasm_val_vec_t res = WASM_EMPTY_VEC;

  wasm_engine_t *(*wasm_engine_new) ();
  void (*wat2wasm) (const wasm_byte_vec_t *wat, wasm_byte_vec_t *out);
  wasm_module_t *(*wasm_module_new) (wasm_store_t *, const wasm_byte_vec_t *binary);
  wasm_store_t *(*wasm_store_new) (wasm_engine_t *);
  wasm_instance_t *(*wasm_instance_new) (wasm_store_t *, const wasm_module_t *, const wasm_extern_vec_t *imports, wasm_trap_t **);
  void (*wasm_instance_exports) (const wasm_instance_t *, wasm_extern_vec_t *out);
  wasm_func_t *(*wasm_extern_as_func) (wasm_extern_t *);
  void (*wasm_module_delete) (wasm_module_t *);
  void (*wasm_instance_delete) (wasm_instance_t *);
  void (*wasm_store_delete) (wasm_store_t *);
  void (*wasm_engine_delete) (wasm_engine_t *);
  void (*wasm_byte_vec_new) (wasm_byte_vec_t *, size_t, const char *);
  void (*wasm_byte_vec_delete) (wasm_byte_vec_t *);
  void (*wasm_importtype_vec_delete) (wasm_importtype_vec_t *);
  void (*wasm_extern_vec_delete) (wasm_extern_vec_t *);
  void (*wasm_byte_vec_new_uninitialized) (wasm_byte_vec_t *, size_t);
  void (*wasm_extern_vec_new_uninitialized) (wasm_extern_vec_t *, size_t);
  void (*wasi_config_capture_stdout) (struct wasi_config_t *);
  void (*wasm_module_imports) (const wasm_module_t *, wasm_importtype_vec_t *);
  void (*wasm_func_delete) (wasm_func_t *);
  wasm_trap_t *(*wasm_func_call) (const wasm_func_t *, const wasm_val_vec_t *args, wasm_val_vec_t *results);
  wasi_config_t *(*wasi_config_new) (const char *);
  wasi_env_t *(*wasi_env_new) (struct wasi_config_t *);
  bool (*wasi_get_imports) (const wasm_store_t *, const wasm_module_t *, const struct wasi_env_t *, wasm_extern_vec_t *);
  wasm_func_t *(*wasi_get_start_function) (wasm_instance_t *);
  intptr_t (*wasi_env_read_stdout) (struct wasi_env_t *, char *, uintptr_t);
  void (*wasi_env_delete) (struct wasi_env_t *);
  void (*wasi_config_arg) (struct wasi_config_t *config, const char *arg);

  wat2wasm = dlsym (cookie, "wat2wasm");
  wasm_module_delete = dlsym (cookie, "wasm_module_delete");
  wasm_instance_delete = dlsym (cookie, "wasm_instance_delete");
  wasm_engine_delete = dlsym (cookie, "wasm_engine_delete");
  wasm_store_delete = dlsym (cookie, "wasm_store_delete");
  wasm_func_call = dlsym (cookie, "wasm_func_call");
  wasm_extern_as_func = dlsym (cookie, "wasm_extern_as_func");
  wasm_instance_exports = dlsym (cookie, "wasm_instance_exports");
  wasm_instance_new = dlsym (cookie, "wasm_instance_new");
  wasm_store_new = dlsym (cookie, "wasm_store_new");
  wasm_module_new = dlsym (cookie, "wasm_module_new");
  wasm_engine_new = dlsym (cookie, "wasm_engine_new");
  wasm_byte_vec_new = dlsym (cookie, "wasm_byte_vec_new");
  wasm_byte_vec_delete = dlsym (cookie, "wasm_byte_vec_delete");
  wasm_extern_vec_delete = dlsym (cookie, "wasm_extern_vec_delete");
  wasm_importtype_vec_delete = dlsym (cookie, "wasm_importtype_vec_delete");
  wasm_byte_vec_new_uninitialized = dlsym (cookie, "wasm_byte_vec_new_uninitialized");
  wasi_config_new = dlsym (cookie, "wasi_config_new");
  wasi_config_arg = dlsym (cookie, "wasi_config_arg");
  wasi_config_capture_stdout = dlsym (cookie, "wasi_config_capture_stdout");
  wasi_env_new = dlsym (cookie, "wasi_env_new");
  wasm_module_imports = dlsym (cookie, "wasm_module_imports");
  wasm_extern_vec_new_uninitialized = dlsym (cookie, "wasm_extern_vec_new_uninitialized");
  wasi_get_imports = dlsym (cookie, "wasi_get_imports");
  wasi_get_start_function = dlsym (cookie, "wasi_get_start_function");
  wasi_env_read_stdout = dlsym (cookie, "wasi_env_read_stdout");
  wasi_env_delete = dlsym (cookie, "wasi_env_delete");
  wasm_func_delete = dlsym (cookie, "wasm_func_delete");

  if (wat2wasm == NULL || wasm_module_delete == NULL || wasm_instance_delete == NULL
      || wasm_engine_delete == NULL || wasm_store_delete == NULL || wasm_func_call == NULL
      || wasm_extern_as_func == NULL || wasm_instance_exports == NULL || wasm_instance_new == NULL
      || wasm_store_new == NULL || wasm_engine_new == NULL || wasm_byte_vec_new == NULL
      || wasm_byte_vec_delete == NULL || wasm_extern_vec_delete == NULL
      || wasm_byte_vec_new_uninitialized == NULL || wasi_config_new == NULL
      || wasi_config_capture_stdout == NULL || wasi_env_new == NULL || wasm_module_imports == NULL
      || wasi_env_read_stdout == NULL || wasi_env_delete == NULL || wasm_func_delete == NULL
      || wasm_importtype_vec_delete == NULL || wasm_extern_vec_new_uninitialized == NULL
      || wasi_get_imports == NULL || wasi_get_start_function == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in `libwasmer.so`");

  wat_wasm_file = fopen (pathname, "rb");

  if (! wat_wasm_file)
    error (EXIT_FAILURE, errno, "error opening wat/wasm module");

  fseek (wat_wasm_file, 0L, SEEK_END);
  file_size = ftell (wat_wasm_file);
  fseek (wat_wasm_file, 0L, SEEK_SET);

  wasm_byte_vec_new_uninitialized (&binary_bytes, file_size);

  if (fread (binary_bytes.data, file_size, 1, wat_wasm_file) != 1)
    error (EXIT_FAILURE, errno, "error loading wat/wasm module");

  /* We can close entrypoint file.   */
  fclose (wat_wasm_file);

  /* We have received a wat file: convert wat to wasm.   */
  if (has_suffix (pathname, "wat") > 0)
    {
      wat2wasm (&binary_bytes, &wasm_bytes);
      binary_bytes = wasm_bytes;
    }

  engine = wasm_engine_new ();
  store = wasm_store_new (engine);

  module = wasm_module_new (store, &binary_bytes);

  if (! module)
    error (EXIT_FAILURE, 0, "error compiling wasm module");

  config = wasi_config_new ("crun_wasi_program");

  /* Count number of external arguments given.  */
  for (arg = argv; *arg != NULL; ++arg)
    args_size++;

  if (args_size > 1)
    {
      wasi_args = str_join_array (1, args_size, argv, " ");
      wasi_config_arg (config, wasi_args);
    }

  wasi_config_capture_stdout (config);
  wasi_env = wasi_env_new (config);
  if (! wasi_env)
    {
      error (EXIT_FAILURE, 0, "error building wasi env");
    }

  /* Instantiate.  */
  wasm_module_imports (module, &import_types);

  wasm_extern_vec_new_uninitialized (&imports, import_types.size);
  wasm_importtype_vec_delete (&import_types);

  if (! wasi_get_imports (store, module, wasi_env, &imports))
    error (EXIT_FAILURE, 0, "error getting WASI imports");

  instance = wasm_instance_new (store, module, &imports, NULL);

  if (! instance)
    error (EXIT_FAILURE, 0, "error instantiating module");

  /* Extract export.  */
  wasm_instance_exports (instance, &exports);
  if (exports.size == 0)
    error (EXIT_FAILURE, 0, "error getting instance exports");

  run_func = wasi_get_start_function (instance);
  if (run_func == NULL)
    error (EXIT_FAILURE, 0, "error accessing export");

  wasm_module_delete (module);
  wasm_instance_delete (instance);

  if (wasm_func_call (run_func, &args, &res))
    error (EXIT_FAILURE, 0, "error calling wasm function");

  do
    {
      data_read_size = wasi_env_read_stdout (wasi_env, buffer, WASMER_BUF_SIZE);

      if (data_read_size > 0)
        {
          /* Relay wasi output to stdout.  */
          ret = safe_write (STDOUT_FILENO, buffer, (ssize_t) data_read_size);
          if (UNLIKELY (ret < 0))
            error (EXIT_FAILURE, errno, "error while writing wasi output to stdout");
        }
  } while (WASMER_BUF_SIZE == data_read_size);

  wasm_extern_vec_delete (&exports);
  wasm_extern_vec_delete (&imports);

  /* Shut down.  */
  wasm_func_delete (run_func);
  wasi_env_delete (wasi_env);
  wasm_store_delete (store);
  wasm_engine_delete (engine);

  exit (EXIT_SUCCESS);
}

static int
libwasmer_load (void **cookie, libcrun_error_t *err arg_unused)
{
  void *handle;

  handle = dlopen ("libwasmer.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libwasmer.so`: %s", dlerror ());
  *cookie = handle;

  return 0;
}

static int
libwasmer_unload (void *cookie, libcrun_error_t *err arg_unused)
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
libwasmer_can_handle_container (libcrun_container_t *container, libcrun_error_t *err arg_unused)
{
  return wasm_can_handle_container (container, err);
}

struct custom_handler_s handler_wasmer = {
  .name = "wasmer",
  .alias = "wasm",
  .feature_string = "WASM:wasmer",
  .load = libwasmer_load,
  .unload = libwasmer_unload,
  .run_func = libwasmer_exec,
  .can_handle_container = libwasmer_can_handle_container,
};

#endif
