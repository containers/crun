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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_WASMTIME
#  include <wasm.h>
#  include <wasi.h>
#  include <wasmtime.h>
#endif

#if HAVE_DLOPEN && HAVE_WASMTIME
static void
libwasmtime_run_module (void *cookie, char *const argv[], wasm_engine_t *engine, wasm_byte_vec_t *wasm);

static void
libwasmtime_run_component (void *cookie, char *const argv[], wasm_engine_t *engine, wasm_byte_vec_t *wasm);

static int
libwasmtime_exec (void *cookie, libcrun_container_t *container arg_unused,
                  const char *pathname, char *const argv[])
{
  wasm_byte_vec_t error_message;
  wasm_byte_vec_t wasm_bytes;
  wasm_engine_t *(*wasm_engine_new) ();
  wasmtime_error_t *(*wasmtime_wat2wasm) (const char *wat, size_t wat_len, wasm_byte_vec_t *out);
  void (*wasm_byte_vec_new_uninitialized) (wasm_byte_vec_t *, size_t);
  void (*wasm_byte_vec_delete) (wasm_byte_vec_t *);
  wasmtime_error_t *(*wasmtime_module_validate) (wasm_engine_t *engine, const uint8_t *wasm, size_t wasm_len);
  void (*wasmtime_error_message) (const wasmtime_error_t *error, wasm_name_t *message);
  void (*wasmtime_error_delete) (wasmtime_error_t *error);

  wasmtime_wat2wasm = dlsym (cookie, "wasmtime_wat2wasm");
  wasm_engine_new = dlsym (cookie, "wasm_engine_new");
  wasm_byte_vec_new_uninitialized = dlsym (cookie, "wasm_byte_vec_new_uninitialized");
  wasm_byte_vec_delete = dlsym (cookie, "wasm_byte_vec_delete");
  wasmtime_module_validate = dlsym (cookie, "wasmtime_module_validate");
  wasmtime_error_delete = dlsym (cookie, "wasmtime_error_delete");
  wasmtime_error_message = dlsym (cookie, "wasmtime_error_message");

  if (wasmtime_wat2wasm == NULL
      || wasm_engine_new == NULL
      || wasm_byte_vec_new_uninitialized == NULL
      || wasm_byte_vec_delete == NULL
      || wasmtime_module_validate == NULL
      || wasmtime_error_delete == NULL
      || wasmtime_error_message == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in `libwasmtime.so`");

  // Set up wasmtime context
  wasm_engine_t *engine = wasm_engine_new ();
  if (engine == NULL)
    error (EXIT_FAILURE, 0, "could not create WebAssembly engine");

  wasm_byte_vec_t wasm;
  // Load and parse container entrypoint
  FILE *file = fopen (pathname, "rbe");
  if (! file)
    error (EXIT_FAILURE, 0, "error loading entrypoint");
  if (fseek (file, 0L, SEEK_END))
    error (EXIT_FAILURE, 0, "error fully loading entrypoint");
  size_t file_size = ftell (file);
  wasm_byte_vec_new_uninitialized (&wasm, file_size);
  if (fseek (file, 0L, SEEK_SET))
    error (EXIT_FAILURE, 0, "error resetting entrypoint");
  if (fread (wasm.data, file_size, 1, file) != 1)
    error (EXIT_FAILURE, 0, "error reading entrypoint");
  fclose (file);

  // If entrypoint contains a webassembly text format
  // compile it on the fly and convert to equivalent
  // binary format.
  if (has_suffix (pathname, ".wat") > 0)
    {
      wasmtime_error_t *err = wasmtime_wat2wasm ((char *) wasm.data, file_size, &wasm_bytes);
      if (err != NULL)
        {
          wasmtime_error_message (err, &error_message);
          wasmtime_error_delete (err);
          error (EXIT_FAILURE, 0, "failed while compiling wat to wasm binary : %.*s", (int) error_message.size, error_message.data);
        }
      wasm_byte_vec_delete (&wasm);
      wasm = wasm_bytes;
    }

  wasm_encoding_t wasm_enc = wasm_interpret_header (wasm.data, wasm.size);
  if (wasm_enc == WASM_ENC_INVALID)
    error (EXIT_FAILURE, 0, "invalid wasm binary header");

  if (wasm_enc == WASM_ENC_MODULE)
    libwasmtime_run_module (cookie, argv, engine, &wasm);
  else if (wasm_enc == WASM_ENC_COMPONENT)
    libwasmtime_run_component (cookie, argv, engine, &wasm);
  else
    error (EXIT_FAILURE, 0, "unsupported wasm encoding detected");

  exit (EXIT_SUCCESS);
}

static void
libwasmtime_run_module (void *cookie, char *const argv[], wasm_engine_t *engine, wasm_byte_vec_t *wasm)
{
  size_t args_size = 0;
  char *const *arg;
  wasm_byte_vec_t error_message;

  // Load needed functions
  void (*wasm_engine_delete) (wasm_engine_t *);
  void (*wasm_byte_vec_delete) (wasm_byte_vec_t *);
  wasi_config_t *(*wasi_config_new) (const char *);
  wasmtime_store_t *(*wasmtime_store_new) (wasm_engine_t *engine, void *data, void (*finalizer) (void *));
  wasmtime_context_t *(*wasmtime_store_context) (wasmtime_store_t *store);
  wasmtime_linker_t *(*wasmtime_linker_new) (wasm_engine_t *engine);
  wasmtime_error_t *(*wasmtime_linker_define_wasi) (wasmtime_linker_t *linker);
  wasmtime_error_t *(*wasmtime_module_new) (
      wasm_engine_t *engine,
      const uint8_t *wasm,
      size_t wasm_len,
      wasmtime_module_t **ret);
  void (*wasi_config_inherit_argv) (wasi_config_t *config);
  void (*wasi_config_inherit_env) (wasi_config_t *config);
  void (*wasi_config_set_argv) (wasi_config_t *config, int argc, const char *argv[]);
  void (*wasi_config_inherit_stdin) (wasi_config_t *config);
  void (*wasi_config_inherit_stdout) (wasi_config_t *config);
  void (*wasi_config_inherit_stderr) (wasi_config_t *config);
  wasmtime_error_t *(*wasmtime_context_set_wasi) (wasmtime_context_t *context, wasi_config_t *wasi);
  wasmtime_error_t *(*wasmtime_linker_module) (
      wasmtime_linker_t *linker,
      wasmtime_context_t *store,
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
      wasmtime_context_t *store,
      const wasmtime_func_t *func,
      const wasmtime_val_t *args,
      size_t nargs,
      wasmtime_val_t *results,
      size_t nresults,
      wasm_trap_t **trap);
  void (*wasmtime_module_delete) (wasmtime_module_t *m);
  void (*wasmtime_store_delete) (wasmtime_store_t *store);
  void (*wasmtime_error_message) (const wasmtime_error_t *error, wasm_name_t *message);
  void (*wasmtime_error_delete) (wasmtime_error_t *error);
  bool (*wasi_config_preopen_dir) (
      wasi_config_t *config,
      const char *path,
      const char *guest_path,
      wasi_dir_perms dir_perms,
      wasi_file_perms file_perms);

  wasm_engine_delete = dlsym (cookie, "wasm_engine_delete");
  wasm_byte_vec_delete = dlsym (cookie, "wasm_byte_vec_delete");
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

  if (wasm_engine_delete == NULL || wasm_byte_vec_delete == NULL
      || wasi_config_new == NULL || wasmtime_store_new == NULL
      || wasmtime_store_context == NULL || wasmtime_linker_new == NULL || wasmtime_linker_define_wasi == NULL
      || wasmtime_module_new == NULL || wasi_config_inherit_argv == NULL || wasi_config_inherit_stdout == NULL
      || wasi_config_inherit_stdin == NULL || wasi_config_inherit_stderr == NULL
      || wasi_config_inherit_env == NULL || wasmtime_context_set_wasi == NULL
      || wasmtime_linker_module == NULL || wasmtime_linker_get_default == NULL || wasmtime_func_call == NULL
      || wasmtime_module_delete == NULL || wasmtime_store_delete == NULL || wasi_config_set_argv == NULL
      || wasmtime_error_delete == NULL || wasmtime_error_message == NULL || wasi_config_preopen_dir == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in `libwasmtime.so`");

  // Set up wasmtime context
  wasmtime_store_t *store = wasmtime_store_new (engine, NULL, NULL);
  if (store == NULL)
    error (EXIT_FAILURE, 0, "could not create WebAssembly store");
  wasmtime_context_t *context = wasmtime_store_context (store);

  // Link with wasi functions defined
  wasmtime_linker_t *linker = wasmtime_linker_new (engine);
  wasmtime_error_t *err = wasmtime_linker_define_wasi (linker);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to link wasi: %.*s", (int) error_message.size, error_message.data);
    }

  // Compile wasm modules
  wasmtime_module_t *module = NULL;
  err = wasmtime_module_new (engine, (uint8_t *) wasm->data, wasm->size, &module);
  if (! module)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to compile module: %.*s", (int) error_message.size, error_message.data);
    }
  wasm_byte_vec_delete (wasm);

  // Init WASI program
  wasi_config_t *wasi_config = wasi_config_new ("crun_wasi_program");
  if (wasi_config == NULL)
    error (EXIT_FAILURE, 0, "could not create WASI configuration");

  // Calculate argc for `wasi_config_set_argv`
  for (arg = argv; *arg != NULL; ++arg)
    args_size++;

  wasi_config_set_argv (wasi_config, args_size, (const char **) argv);
  wasi_config_inherit_env (wasi_config);
  wasi_config_inherit_stdin (wasi_config);
  wasi_config_inherit_stdout (wasi_config);
  wasi_config_inherit_stderr (wasi_config);
  wasi_config_preopen_dir (
      wasi_config,
      ".",
      ".",
      WASMTIME_WASI_DIR_PERMS_READ | WASMTIME_WASI_DIR_PERMS_WRITE,
      WASMTIME_WASI_FILE_PERMS_READ | WASMTIME_WASI_FILE_PERMS_WRITE);
  wasm_trap_t *trap = NULL;
  err = wasmtime_context_set_wasi (context, wasi_config);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to instantiate WASI: %.*s", (int) error_message.size, error_message.data);
    }

  // Init module
  err = wasmtime_linker_module (linker, context, "", 0, module);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to instantiate module: %.*s", (int) error_message.size, error_message.data);
    }

  // Actually run our .wasm
  wasmtime_func_t func;
  err = wasmtime_linker_get_default (linker, context, "", 0, &func);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to locate default export for module %.*s", (int) error_message.size, error_message.data);
    }

  err = wasmtime_func_call (context, &func, NULL, 0, NULL, 0, &trap);
  if (err != NULL || trap != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "error calling default export: %.*s", (int) error_message.size, error_message.data);
    }

  // Clean everything
  wasmtime_module_delete (module);
  wasmtime_store_delete (store);
  wasm_engine_delete (engine);
}

static void
libwasmtime_run_component (void *cookie, char *const argv[], wasm_engine_t *engine, wasm_byte_vec_t *wasm)
{
  const char *const wasi_cli_run_interface = "wasi:cli/run@0.2.0";
  const char *const wasi_cli_run_interface_run = "run";
  char *const *arg;
  wasm_byte_vec_t error_message;

  // Load needed functions
  void (*wasm_engine_delete) (wasm_engine_t *);
  void (*wasm_byte_vec_delete) (wasm_byte_vec_t *);
  wasmtime_store_t *(*wasmtime_store_new) (wasm_engine_t *engine, void *data, void (*finalizer) (void *));
  void (*wasmtime_store_delete) (wasmtime_store_t *store);
  wasmtime_context_t *(*wasmtime_store_context) (wasmtime_store_t *store);
  wasmtime_error_t *(*wasmtime_component_new) (
      const wasm_engine_t *engine,
      const uint8_t *buf,
      size_t len,
      wasmtime_component_t **component_out);
  wasmtime_wasip2_config_t *(*wasmtime_wasip2_config_new) (void);
  void (*wasi_config_inherit_env) (wasi_config_t *config);
  void (*wasmtime_wasip2_config_inherit_stdin) (wasmtime_wasip2_config_t *config);
  void (*wasmtime_wasip2_config_inherit_stdout) (wasmtime_wasip2_config_t *config);
  void (*wasmtime_wasip2_config_inherit_stderr) (wasmtime_wasip2_config_t *config);
  void (*wasmtime_wasip2_config_arg) (wasmtime_wasip2_config_t *config, const char *arg, size_t arg_len);
  void (*wasmtime_context_set_wasip2) (wasmtime_context_t *context, wasmtime_wasip2_config_t *config);
  wasmtime_component_linker_t *(*wasmtime_component_linker_new) (wasm_engine_t *engine);
  wasmtime_error_t *(*wasmtime_component_linker_add_wasip2) (wasmtime_component_linker_t *linker);
  wasmtime_error_t *(*wasmtime_component_linker_instantiate) (
      const wasmtime_component_linker_t *linker,
      wasmtime_context_t *context,
      const wasmtime_component_t *component,
      wasmtime_component_instance_t *instance_out);
  wasmtime_component_export_index_t *(*wasmtime_component_instance_get_export_index) (
      const wasmtime_component_instance_t *instance,
      wasmtime_context_t *context,
      const wasmtime_component_export_index_t *instance_export_index,
      const char *name,
      size_t name_len);
  bool (*wasmtime_component_instance_get_func) (
      const wasmtime_component_instance_t *instance,
      wasmtime_context_t *context,
      const wasmtime_component_export_index_t *export_index,
      wasmtime_component_func_t *func_out);
  wasmtime_error_t *(*wasmtime_component_func_call) (
      const wasmtime_component_func_t *func,
      wasmtime_context_t *context,
      const wasmtime_component_val_t *args,
      size_t args_size,
      wasmtime_component_val_t *results,
      size_t results_size);
  void (*wasmtime_component_export_index_delete) (wasmtime_component_export_index_t *export_index);
  void (*wasmtime_component_delete) (wasmtime_component_t *c);
  void (*wasmtime_component_linker_delete) (wasmtime_component_linker_t *linker);
  void (*wasmtime_error_message) (const wasmtime_error_t *error, wasm_name_t *message);
  void (*wasmtime_error_delete) (wasmtime_error_t *error);
  bool (*wasi_config_preopen_dir) (
      wasi_config_t *config,
      const char *path,
      const char *guest_path,
      wasi_dir_perms dir_perms,
      wasi_file_perms file_perms);

  wasm_engine_delete = dlsym (cookie, "wasm_engine_delete");
  wasm_byte_vec_delete = dlsym (cookie, "wasm_byte_vec_delete");
  wasmtime_store_new = dlsym (cookie, "wasmtime_store_new");
  wasmtime_store_delete = dlsym (cookie, "wasmtime_store_delete");
  wasmtime_store_context = dlsym (cookie, "wasmtime_store_context");
  wasmtime_component_new = dlsym (cookie, "wasmtime_component_new");
  wasmtime_wasip2_config_new = dlsym (cookie, "wasmtime_wasip2_config_new");
  wasi_config_inherit_env = dlsym (cookie, "wasi_config_inherit_env");
  wasmtime_wasip2_config_inherit_stdin = dlsym (cookie, "wasmtime_wasip2_config_inherit_stdin");
  wasmtime_wasip2_config_inherit_stdout = dlsym (cookie, "wasmtime_wasip2_config_inherit_stdout");
  wasmtime_wasip2_config_inherit_stderr = dlsym (cookie, "wasmtime_wasip2_config_inherit_stderr");
  wasmtime_wasip2_config_arg = dlsym (cookie, "wasmtime_wasip2_config_arg");
  wasmtime_context_set_wasip2 = dlsym (cookie, "wasmtime_context_set_wasip2");
  wasmtime_component_linker_new = dlsym (cookie, "wasmtime_component_linker_new");
  wasmtime_component_linker_add_wasip2 = dlsym (cookie, "wasmtime_component_linker_add_wasip2");
  wasmtime_component_linker_instantiate = dlsym (cookie, "wasmtime_component_linker_instantiate");
  wasmtime_component_instance_get_export_index = dlsym (cookie, "wasmtime_component_instance_get_export_index");
  wasmtime_component_instance_get_func = dlsym (cookie, "wasmtime_component_instance_get_func");
  wasmtime_component_func_call = dlsym (cookie, "wasmtime_component_func_call");
  wasmtime_component_export_index_delete = dlsym (cookie, "wasmtime_component_export_index_delete");
  wasmtime_component_delete = dlsym (cookie, "wasmtime_component_delete");
  wasmtime_component_linker_delete = dlsym (cookie, "wasmtime_component_linker_delete");
  wasmtime_error_message = dlsym (cookie, "wasmtime_error_message");
  wasmtime_error_delete = dlsym (cookie, "wasmtime_error_delete");
  wasi_config_preopen_dir = dlsym (cookie, "wasi_config_preopen_dir");

  if (wasm_engine_delete == NULL || wasm_byte_vec_delete == NULL || wasmtime_store_new == NULL
      || wasmtime_store_delete == NULL || wasmtime_store_context == NULL || wasmtime_component_new == NULL
      || wasmtime_wasip2_config_new == NULL || wasi_config_inherit_env == NULL || wasmtime_wasip2_config_inherit_stdin == NULL
      || wasmtime_wasip2_config_inherit_stdout == NULL || wasmtime_wasip2_config_inherit_stderr == NULL || wasmtime_wasip2_config_arg == NULL
      || wasmtime_context_set_wasip2 == NULL || wasmtime_component_linker_new == NULL || wasmtime_component_linker_add_wasip2 == NULL
      || wasmtime_component_linker_instantiate == NULL || wasmtime_component_instance_get_export_index == NULL
      || wasmtime_component_instance_get_func == NULL || wasmtime_component_func_call == NULL || wasmtime_component_export_index_delete == NULL
      || wasmtime_component_delete == NULL || wasmtime_component_linker_delete == NULL || wasmtime_error_message == NULL
      || wasmtime_error_delete == NULL || wasi_config_preopen_dir == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in `libwasmtime.so`");

  // Set up wasmtime context
  wasmtime_store_t *store = wasmtime_store_new (engine, NULL, NULL);
  if (store == NULL)
    error (EXIT_FAILURE, 0, "could not create WebAssembly store");
  wasmtime_context_t *context = wasmtime_store_context (store);

  // Compile wasm component
  wasmtime_component_t *component = NULL;
  wasmtime_error_t *err = wasmtime_component_new (engine, (uint8_t *) wasm->data, wasm->size, &component);
  if (! component || err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to compile component: %.*s", (int) error_message.size, error_message.data);
    }
  wasm_byte_vec_delete (wasm);

  // Set up WASIp2 config
  wasmtime_wasip2_config_t *wasi_config = wasmtime_wasip2_config_new ();
  if (wasi_config == NULL)
    error (EXIT_FAILURE, 0, "could not create WASIp2 configuration");

  wasi_config_inherit_env ((wasi_config_t *) wasi_config);
  wasmtime_wasip2_config_inherit_stdin (wasi_config);
  wasmtime_wasip2_config_inherit_stdout (wasi_config);
  wasmtime_wasip2_config_inherit_stderr (wasi_config);
  wasi_config_preopen_dir (
      (wasi_config_t *) wasi_config,
      ".",
      ".",
      WASMTIME_WASI_DIR_PERMS_READ | WASMTIME_WASI_DIR_PERMS_WRITE,
      WASMTIME_WASI_FILE_PERMS_READ | WASMTIME_WASI_FILE_PERMS_WRITE);

  for (arg = argv; *arg != NULL; ++arg)
    wasmtime_wasip2_config_arg (wasi_config, *arg, strlen (*arg));

  wasmtime_context_set_wasip2 (context, wasi_config);

  // Get wasi exposing linker
  wasmtime_component_linker_t *linker = wasmtime_component_linker_new (engine);
  err = wasmtime_component_linker_add_wasip2 (linker);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to add WASIp2 to linker: %.*s", (int) error_message.size, error_message.data);
    }

  // Instantiate the component
  wasmtime_component_instance_t component_inst = {};
  err = wasmtime_component_linker_instantiate (linker, context, component, &component_inst);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to instantiate component: %.*s", (int) error_message.size, error_message.data);
    }

  // Get index of the run interface in wasi/cli world
  wasmtime_component_export_index_t *run_interface_idx = wasmtime_component_instance_get_export_index (
      &component_inst,
      context,
      NULL,
      wasi_cli_run_interface,
      strlen (wasi_cli_run_interface));
  if (run_interface_idx == NULL)
    error (EXIT_FAILURE, 0, "failed to fetch export index of %.*s", (int) strlen (wasi_cli_run_interface), wasi_cli_run_interface);
  // Get index of the run function
  wasmtime_component_export_index_t *run_func_idx = wasmtime_component_instance_get_export_index (
      &component_inst,
      context,
      run_interface_idx,
      wasi_cli_run_interface_run,
      strlen (wasi_cli_run_interface_run));
  if (run_func_idx == NULL)
    error (EXIT_FAILURE, 0, "failed to fetch export index of %.*s", (int) strlen (wasi_cli_run_interface_run), wasi_cli_run_interface_run);

  // Actually retrieve the func
  wasmtime_component_func_t run_func = {};
  if (! wasmtime_component_instance_get_func (&component_inst, context, run_func_idx, &run_func))
    error (EXIT_FAILURE, 0, "failed to retrieve run function");

  // Call the func
  wasmtime_component_val_t result = {};
  err = wasmtime_component_func_call (&run_func, context, NULL, 0, &result, 1);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "error calling run function: %.*s", (int) error_message.size, error_message.data);
    }

  // Clean everything
  wasmtime_component_export_index_delete (run_func_idx);
  wasmtime_component_export_index_delete (run_interface_idx);
  wasmtime_component_linker_delete (linker);
  wasmtime_component_delete (component);
  wasmtime_store_delete (store);
  wasm_engine_delete (engine);
}

static int
libwasmtime_load (void **cookie, libcrun_error_t *err)
{
  void *handle;

  handle = dlopen ("libwasmtime.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libwasmtime.so`: %s", dlerror ());
  *cookie = handle;

  return 0;
}

static int
libwasmtime_unload (void *cookie, libcrun_error_t *err)
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
libwasmtime_can_handle_container (libcrun_container_t *container, libcrun_error_t *err)
{
  return wasm_can_handle_container (container, err);
}

struct custom_handler_s handler_wasmtime = {
  .name = "wasmtime",
  .alias = "wasm",
  .feature_string = "WASM:wasmtime",
  .load = libwasmtime_load,
  .unload = libwasmtime_unload,
  .run_func = libwasmtime_exec,
  .can_handle_container = libwasmtime_can_handle_container,
};

#endif
