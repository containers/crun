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
#  define WASMTIME_COMMON_SYMBOLS(cookie)                                                \
    void (*wasm_byte_vec_delete) (wasm_byte_vec_t *)                                     \
        = libwasmtime_load_symbol ((cookie), "wasm_byte_vec_delete");                    \
    void (*wasmtime_error_message) (const wasmtime_error_t *error, wasm_name_t *message) \
        = libwasmtime_load_symbol ((cookie), "wasmtime_error_message");                  \
    bool (*wasmtime_error_exit_status) (const wasmtime_error_t *error, int *status)      \
        = libwasmtime_load_symbol ((cookie), "wasmtime_error_exit_status");              \
    void (*wasmtime_error_delete) (wasmtime_error_t * error)                             \
        = libwasmtime_load_symbol ((cookie), "wasmtime_error_delete");

static void *
libwasmtime_load_symbol (void *cookie, char *const symbol);

struct libwasmtime_vm
{
  wasm_engine_t *engine;
  wasmtime_store_t *store;
  wasmtime_context_t *context;
#  if WASMTIME_VERSION_MAJOR < 39
  wasi_config_t *config;
#  endif
};

static struct libwasmtime_vm *
libwasmtime_setup_vm (void *cookie, char *const argv[], struct libwasmtime_vm *vm)
{
  size_t args_size = 0;
  char *const *arg;
  wasm_byte_vec_t error_message;

  if (vm == NULL)
    error (EXIT_FAILURE, 0, "internal error: cannot setup a NULL vm");

  // Load needed functions
  WASMTIME_COMMON_SYMBOLS (cookie)
  wasm_engine_t *(*wasm_engine_new) ()
      = libwasmtime_load_symbol (cookie, "wasm_engine_new");
  wasmtime_linker_t *(*wasmtime_linker_new) (wasm_engine_t *engine)
      = libwasmtime_load_symbol (cookie, "wasmtime_linker_new");
  wasmtime_store_t *(*wasmtime_store_new) (wasm_engine_t *engine, void *data, void (*finalizer) (void *))
      = libwasmtime_load_symbol (cookie, "wasmtime_store_new");
  wasmtime_context_t *(*wasmtime_store_context) (wasmtime_store_t *store)
      = libwasmtime_load_symbol (cookie, "wasmtime_store_context");
  wasi_config_t *(*wasi_config_new) (const char *)
      = libwasmtime_load_symbol (cookie, "wasi_config_new");
  void (*wasi_config_set_argv) (wasi_config_t *config, int argc, const char *argv[])
      = libwasmtime_load_symbol (cookie, "wasi_config_set_argv");
  void (*wasi_config_inherit_env) (wasi_config_t *config)
      = libwasmtime_load_symbol (cookie, "wasi_config_inherit_env");
  void (*wasi_config_inherit_stdin) (wasi_config_t *config)
      = libwasmtime_load_symbol (cookie, "wasi_config_inherit_stdin");
  void (*wasi_config_inherit_stdout) (wasi_config_t *config)
      = libwasmtime_load_symbol (cookie, "wasi_config_inherit_stdout");
  void (*wasi_config_inherit_stderr) (wasi_config_t *config)
      = libwasmtime_load_symbol (cookie, "wasi_config_inherit_stderr");
  bool (*wasi_config_preopen_dir) (
      wasi_config_t *config,
      const char *path,
      const char *guest_path,
      wasi_dir_perms dir_perms,
      wasi_file_perms file_perms)
      = libwasmtime_load_symbol (cookie, "wasi_config_preopen_dir");
#  if WASMTIME_VERSION_MAJOR >= 39
  wasmtime_error_t *(*wasmtime_context_set_wasi) (wasmtime_context_t *context, wasi_config_t *wasi)
      = libwasmtime_load_symbol (cookie, "wasmtime_context_set_wasi");
#  endif

  // Set up WebAssembly engine
  vm->engine = wasm_engine_new ();
  if (vm->engine == NULL)
    error (EXIT_FAILURE, 0, "could not create WebAssembly engine");

  // Set up wasmtime context
  vm->store = wasmtime_store_new (vm->engine, NULL, NULL);
  if (vm->store == NULL)
    error (EXIT_FAILURE, 0, "could not create WebAssembly store");
  vm->context = wasmtime_store_context (vm->store);

  // Init WASI program
  wasi_config_t *config = wasi_config_new ("crun_wasi_program");
  if (config == NULL)
    error (EXIT_FAILURE, 0, "could not create WASI configuration");

  // Calculate argc for `wasi_config_set_argv`
  for (arg = argv; *arg != NULL; ++arg)
    args_size++;

  wasi_config_set_argv (config, args_size, (const char **) argv);
  wasi_config_inherit_env (config);
  wasi_config_inherit_stdin (config);
  wasi_config_inherit_stdout (config);
  wasi_config_inherit_stderr (config);
  wasi_config_preopen_dir (
      config,
      ".",
      ".",
      WASMTIME_WASI_DIR_PERMS_READ | WASMTIME_WASI_DIR_PERMS_WRITE,
      WASMTIME_WASI_FILE_PERMS_READ | WASMTIME_WASI_FILE_PERMS_WRITE);

#  if WASMTIME_VERSION_MAJOR >= 39
  // If we are compiling wasmtime against 39 or higher
  // we can make use of the unified wasi API.
  wasmtime_error_t *err = wasmtime_context_set_wasi (vm->context, config);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to instantiate WASI: %.*s", (int) error_message.size, error_message.data);
    }
#  else
  // Otherwise let each branching path apply the config.
  vm->config = config;
#  endif

  return vm;
}

static void
libwasmtime_delete_vm (void *cookie, struct libwasmtime_vm *vm)
{
  void (*wasmtime_store_delete) (wasmtime_store_t *store)
      = libwasmtime_load_symbol (cookie, "wasmtime_store_delete");
  void (*wasm_engine_delete) (wasm_engine_t *)
      = libwasmtime_load_symbol (cookie, "wasm_engine_delete");

  wasmtime_store_delete (vm->store);
  wasm_engine_delete (vm->engine);
}

static int
libwasmtime_run_module (void *cookie, struct libwasmtime_vm *vm, wasm_byte_vec_t *wasm);

static int
libwasmtime_run_component (void *cookie, struct libwasmtime_vm *vm, wasm_byte_vec_t *wasm);

static int
libwasmtime_exec (void *cookie, libcrun_container_t *container arg_unused,
                  const char *pathname, char *const argv[])
{
  wasm_byte_vec_t error_message;
  wasm_byte_vec_t wasm_bytes;
  int status;

  WASMTIME_COMMON_SYMBOLS (cookie)
  wasmtime_error_t *(*wasmtime_wat2wasm) (const char *wat, size_t wat_len, wasm_byte_vec_t *out)
      = libwasmtime_load_symbol (cookie, "wasmtime_wat2wasm");
  void (*wasm_byte_vec_new_uninitialized) (wasm_byte_vec_t *, size_t)
      = libwasmtime_load_symbol (cookie, "wasm_byte_vec_new_uninitialized");

  wasm_byte_vec_t wasm;
  // Load and parse container entrypoint
  FILE *file = fopen (pathname, "rbe");
  if (! file)
    error (EXIT_FAILURE, 0, "error loading entrypoint");
  if (fseek (file, 0L, SEEK_END))
    error (EXIT_FAILURE, 0, "error fully loading entrypoint");
  long file_size = ftell (file);
  if (file_size == -1L)
    error (EXIT_FAILURE, 0, "error getting entrypoint size");
  wasm_byte_vec_new_uninitialized (&wasm, (size_t) file_size);
  if (fseek (file, 0L, SEEK_SET))
    error (EXIT_FAILURE, 0, "error resetting entrypoint");
  if (fread (wasm.data, (size_t) file_size, 1, file) != 1)
    error (EXIT_FAILURE, 0, "error reading entrypoint");
  fclose (file);

  // If entrypoint contains a webassembly text format
  // compile it on the fly and convert to equivalent
  // binary format.
  if (has_case_suffix (pathname, ".wat") > 0)
    {
      wasmtime_error_t *err = wasmtime_wat2wasm ((char *) wasm.data, (size_t) file_size, &wasm_bytes);
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

  struct libwasmtime_vm vm = {};
  libwasmtime_setup_vm (cookie, argv, &vm);

  if (wasm_enc == WASM_ENC_MODULE)
    status = libwasmtime_run_module (cookie, &vm, &wasm);
  else if (wasm_enc == WASM_ENC_COMPONENT)
    status = libwasmtime_run_component (cookie, &vm, &wasm);
  else
    error (EXIT_FAILURE, 0, "unsupported wasm encoding detected");

  libwasmtime_delete_vm (cookie, &vm);
  exit (status);
}

static void *
libwasmtime_load_symbol (void *cookie, char *const symbol)
{
  void *sym = dlsym (cookie, symbol);
  if (sym == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in `libwasmtime.so`: %.*s", (int) strlen (symbol), symbol);

  return sym;
}

static int
libwasmtime_run_module (void *cookie, struct libwasmtime_vm *vm, wasm_byte_vec_t *wasm)
{
  wasmtime_error_t *err;
  wasm_byte_vec_t error_message;

  // Load needed functions
  WASMTIME_COMMON_SYMBOLS (cookie)
  wasmtime_linker_t *(*wasmtime_linker_new) (wasm_engine_t *engine)
      = libwasmtime_load_symbol (cookie, "wasmtime_linker_new");
  wasmtime_error_t *(*wasmtime_linker_define_wasi) (wasmtime_linker_t *linker)
      = libwasmtime_load_symbol (cookie, "wasmtime_linker_define_wasi");
  wasmtime_error_t *(*wasmtime_module_new) (
      wasm_engine_t *engine,
      const uint8_t *wasm,
      size_t wasm_len,
      wasmtime_module_t **ret)
      = libwasmtime_load_symbol (cookie, "wasmtime_module_new");
  wasmtime_error_t *(*wasmtime_linker_module) (
      wasmtime_linker_t *linker,
      wasmtime_context_t *store,
      const char *name,
      size_t name_len,
      const wasmtime_module_t *module)
      = libwasmtime_load_symbol (cookie, "wasmtime_linker_module");
  wasmtime_error_t *(*wasmtime_linker_get_default) (
      const wasmtime_linker_t *linker,
      wasmtime_context_t *store,
      const char *name,
      size_t name_len,
      wasmtime_func_t *func)
      = libwasmtime_load_symbol (cookie, "wasmtime_linker_get_default");
  wasmtime_error_t *(*wasmtime_func_call) (
      wasmtime_context_t *store,
      const wasmtime_func_t *func,
      const wasmtime_val_t *args,
      size_t nargs,
      wasmtime_val_t *results,
      size_t nresults,
      wasm_trap_t **trap)
      = libwasmtime_load_symbol (cookie, "wasmtime_func_call");
  void (*wasm_trap_message) (const wasm_trap_t *trap, wasm_message_t *message)
      = libwasmtime_load_symbol (cookie, "wasm_trap_message");
  void (*wasm_trap_delete) (wasm_trap_t *)
      = libwasmtime_load_symbol (cookie, "wasm_trap_delete");
  void (*wasmtime_module_delete) (wasmtime_module_t *m)
      = libwasmtime_load_symbol (cookie, "wasmtime_module_delete");

#  if WASMTIME_VERSION_MAJOR < 39
  wasmtime_error_t *(*wasmtime_context_set_wasi) (wasmtime_context_t *context, wasi_config_t *wasi)
      = libwasmtime_load_symbol (cookie, "wasmtime_context_set_wasi");
  err = wasmtime_context_set_wasi (vm->context, vm->config);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to instantiate WASI: %.*s", (int) error_message.size, error_message.data);
    }
#  endif

  wasmtime_linker_t *linker = wasmtime_linker_new (vm->engine);
  err = wasmtime_linker_define_wasi (linker);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to link wasi: %.*s", (int) error_message.size, error_message.data);
    }

  // Compile wasm modules
  wasmtime_module_t *module = NULL;
  err = wasmtime_module_new (vm->engine, (uint8_t *) wasm->data, wasm->size, &module);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to compile module: %.*s", (int) error_message.size, error_message.data);
    }
  if (module == NULL)
    error (EXIT_FAILURE, 0, "internal error: module is NULL");
  wasm_byte_vec_delete (wasm);

  // Init module
  err = wasmtime_linker_module (linker, vm->context, "", 0, module);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to instantiate module: %.*s", (int) error_message.size, error_message.data);
    }

  // Actually run our .wasm
  wasmtime_func_t func;
  err = wasmtime_linker_get_default (linker, vm->context, "", 0, &func);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to locate default export for module %.*s", (int) error_message.size, error_message.data);
    }

  int status = EXIT_SUCCESS;
  wasm_trap_t *trap = NULL;
  err = wasmtime_func_call (vm->context, &func, NULL, 0, NULL, 0, &trap);
  if (err != NULL && ! wasmtime_error_exit_status (err, &status))
    {
      // The error does not describe an exit code thus we error out.
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "error calling default export: %.*s", (int) error_message.size, error_message.data);
    }
  if (trap != NULL)
    {
      wasm_trap_message (trap, &error_message);
      wasm_trap_delete (trap);
      fprintf (stderr, "trap triggered in module: %.*s", (int) error_message.size, error_message.data);
      status = EXIT_FAILURE;
    }

  // Clean everything
  wasmtime_module_delete (module);

  return status;
}

static int
libwasmtime_run_component (void *cookie, struct libwasmtime_vm *vm, wasm_byte_vec_t *wasm)
{
  const char *const wasi_cli_run_interface = "wasi:cli/run@0.2.0";
  const char *const wasi_cli_run_interface_run = "run";
  char *const *arg;
  wasm_byte_vec_t error_message;

  // Load needed functions
  WASMTIME_COMMON_SYMBOLS (cookie)
  wasmtime_error_t *(*wasmtime_component_new) (
      const wasm_engine_t *engine,
      const uint8_t *buf,
      size_t len,
      wasmtime_component_t **component_out)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_new");
  wasmtime_component_linker_t *(*wasmtime_component_linker_new) (wasm_engine_t *engine)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_linker_new");
  wasmtime_error_t *(*wasmtime_component_linker_add_wasip2) (wasmtime_component_linker_t *linker)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_linker_add_wasip2");
  wasmtime_error_t *(*wasmtime_component_linker_instantiate) (
      const wasmtime_component_linker_t *linker,
      wasmtime_context_t *context,
      const wasmtime_component_t *component,
      wasmtime_component_instance_t *instance_out)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_linker_instantiate");
  wasmtime_component_export_index_t *(*wasmtime_component_instance_get_export_index) (
      const wasmtime_component_instance_t *instance,
      wasmtime_context_t *context,
      const wasmtime_component_export_index_t *instance_export_index,
      const char *name,
      size_t name_len)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_instance_get_export_index");
  bool (*wasmtime_component_instance_get_func) (
      const wasmtime_component_instance_t *instance,
      wasmtime_context_t *context,
      const wasmtime_component_export_index_t *export_index,
      wasmtime_component_func_t *func_out)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_instance_get_func");
  wasmtime_error_t *(*wasmtime_component_func_call) (
      const wasmtime_component_func_t *func,
      wasmtime_context_t *context,
      const wasmtime_component_val_t *args,
      size_t args_size,
      wasmtime_component_val_t *results,
      size_t results_size)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_func_call");
  wasmtime_error_t *(*wasmtime_component_func_post_return) (const wasmtime_component_func_t *func, wasmtime_context_t *context)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_func_post_return");
  void (*wasmtime_component_export_index_delete) (wasmtime_component_export_index_t *export_index)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_export_index_delete");
  void (*wasmtime_component_delete) (wasmtime_component_t *c)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_delete");
  void (*wasmtime_component_linker_delete) (wasmtime_component_linker_t *linker)
      = libwasmtime_load_symbol (cookie, "wasmtime_component_linker_delete");

#  if WASMTIME_VERSION_MAJOR < 39
  void (*wasmtime_context_set_wasip2) (wasmtime_context_t *context, wasmtime_wasip2_config_t *config)
      = libwasmtime_load_symbol (cookie, "wasmtime_context_set_wasip2");
  wasmtime_context_set_wasip2 (vm->context, (wasmtime_wasip2_config_t *) vm->config);
#  endif

  // Compile wasm component
  wasmtime_component_t *component = NULL;
  wasmtime_error_t *err = wasmtime_component_new (vm->engine, (uint8_t *) wasm->data, wasm->size, &component);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to compile component: %.*s", (int) error_message.size, error_message.data);
    }
  if (component == NULL)
    error (EXIT_FAILURE, 0, "internal error: component is NULL");
  wasm_byte_vec_delete (wasm);

  // Get wasi exposing linker
  wasmtime_component_linker_t *linker = wasmtime_component_linker_new (vm->engine);
  err = wasmtime_component_linker_add_wasip2 (linker);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to add WASIp2 to linker: %.*s", (int) error_message.size, error_message.data);
    }

  // Instantiate the component
  wasmtime_component_instance_t component_inst = {};
  err = wasmtime_component_linker_instantiate (linker, vm->context, component, &component_inst);
  if (err != NULL)
    {
      wasmtime_error_message (err, &error_message);
      wasmtime_error_delete (err);
      error (EXIT_FAILURE, 0, "failed to instantiate component: %.*s", (int) error_message.size, error_message.data);
    }

  // Get index of the run interface in wasi/cli world
  wasmtime_component_export_index_t *run_interface_idx = wasmtime_component_instance_get_export_index (
      &component_inst,
      vm->context,
      NULL,
      wasi_cli_run_interface,
      strlen (wasi_cli_run_interface));
  if (run_interface_idx == NULL)
    error (EXIT_FAILURE, 0, "failed to fetch export index of %.*s", (int) strlen (wasi_cli_run_interface), wasi_cli_run_interface);
  // Get index of the run function
  wasmtime_component_export_index_t *run_func_idx = wasmtime_component_instance_get_export_index (
      &component_inst,
      vm->context,
      run_interface_idx,
      wasi_cli_run_interface_run,
      strlen (wasi_cli_run_interface_run));
  if (run_func_idx == NULL)
    error (EXIT_FAILURE, 0, "failed to fetch export index of %.*s", (int) strlen (wasi_cli_run_interface_run), wasi_cli_run_interface_run);

  // Actually retrieve the func
  wasmtime_component_func_t run_func = {};
  if (! wasmtime_component_instance_get_func (&component_inst, vm->context, run_func_idx, &run_func))
    error (EXIT_FAILURE, 0, "failed to retrieve run function");

  // Call the func
  int status = EXIT_SUCCESS;
  bool func_call_caused_error = false;
  wasmtime_component_val_t result = {};
  err = wasmtime_component_func_call (&run_func, vm->context, NULL, 0, &result, 1);
  if (err != NULL)
    {
      if (wasmtime_error_exit_status (err, &status))
        {
          wasmtime_error_delete (err);
          func_call_caused_error = true;
        }
      else
        {
          // The error does not describe an exit code thus we error out.
          wasmtime_error_message (err, &error_message);
          wasmtime_error_delete (err);
          error (EXIT_FAILURE, 0, "error calling run function: %.*s", (int) error_message.size, error_message.data);
        }
    }

  // Call its post-return __only__ if `wasmtime_component_func_call` was successful.
  // Even an error describing an exit code which may be 0 counts as not successful.
  if (! func_call_caused_error)
    {
      err = wasmtime_component_func_post_return (&run_func, vm->context);
      if (err != NULL)
        {
          wasmtime_error_message (err, &error_message);
          wasmtime_error_delete (err);
          error (EXIT_FAILURE, 0, "error calling run function post-return: %.*s", (int) error_message.size, error_message.data);
        }
    }

  // Clean everything
  wasmtime_component_export_index_delete (run_func_idx);
  wasmtime_component_export_index_delete (run_interface_idx);
  wasmtime_component_linker_delete (linker);
  wasmtime_component_delete (component);

  return status;
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
