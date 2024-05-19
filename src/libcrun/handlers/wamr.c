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

#ifdef HAVE_WAMR
// #  include <wasm.h>
// #  include <wasi.h>
#  include <wasm_export.h>
#endif

#if HAVE_DLOPEN && HAVE_WAMR

static int
libwamr_load (void **cookie, libcrun_error_t *err)
{
  void *handle;

  handle = dlopen ("libiwasm.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libiwasm.so`: `%s`", dlerror ());
  *cookie = handle;

  return 0;
}

static int
libwamr_unload (void *cookie, libcrun_error_t *err)
{
  int r;

  if (cookie)
    {
      r = dlclose (cookie);
      if (UNLIKELY (r < 0))
        return crun_make_error (err, 0, "could not unload handle: `%s`", dlerror ());
    }
  return 0;
}

// Function to read a WebAssembly binary file into a buffer
uint8_t *read_wasm_binary_to_buffer(const char *pathname, uint32_t *size) {
    FILE *file;
    uint8_t *buffer;
    size_t file_size;

    // Open the file in binary mode
    file = fopen(pathname, "rb");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    // Seek to the end of the file to determine the size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for the buffer
    buffer = (uint8_t *)malloc(file_size);
    if (!buffer) {
        perror("Failed to allocate memory");
        fclose(file);
        return NULL;
    }

    // Read the file into the buffer
    if (fread(buffer, 1, file_size, file) != file_size) {
        perror("Failed to read file");
        free(buffer);
        fclose(file);
        return NULL;
    }

    // Close the file
    fclose(file);

    // Set the size output parameter
    *size = file_size;

    // Return the buffer
    return buffer;
}

static int
libwamr_exec (void *cookie, __attribute__ ((unused)) libcrun_container_t *container, const char *pathname, char *const argv[])
{
  // load symbols from the shared library libiwasm.so
  bool (*wasm_runtime_init) ();

  uint8_t (*read_wasm_binary_to_buffer) (const char *pathname, uint32_t *size);

  wasm_module_t module;
  wasm_module_t (*wasm_runtime_load) (uint8_t *buf, uint32_t size, char *error_buf, uint32_t error_buf_size);

  wasm_module_inst_t module_inst;
  wasm_module_inst_t (*wasm_runtime_instantiate) (const wasm_module_t module,
                         uint32_t default_stack_size,
                         uint32_t host_managed_heap_size, 
                         char *error_buf,
                         uint32_t error_buf_size);

  wasm_function_inst_t func;
  wasm_function_inst_t (*wasm_runtime_lookup_function) (wasm_module_inst_t const module_inst, const char *name);

  wasm_exec_env_t exec_env;
  wasm_exec_env_t (*wasm_runtime_create_exec_env) (wasm_module_inst_t module_inst, uint32_t stack_size);

  bool (*wasm_runtime_call_wasm) (wasm_exec_env_t exec_env, wasm_function_inst_t function, uint32_t argc, uint32_t argv[]);

  const char *(*wasm_runtime_get_exception)(wasm_module_inst_t module_inst);

  void (*wasm_runtime_destroy_exec_env) (wasm_exec_env_t exec_env);

  void (*wasm_runtime_deinstantiate) (wasm_module_inst_t module_inst);

  void (*wasm_runtime_unload) (wasm_module_t module);

  void (*wasm_runtime_destroy) ();


  wasm_runtime_init = dlsym (cookie, "wasm_runtime_init");
  read_wasm_binary_to_buffer = dlsym (cookie, "read_wasm_binary_to_buffer");
  wasm_runtime_load = dlsym (cookie, "wasm_runtime_load");
  wasm_runtime_instantiate = dlsym (cookie, "wasm_runtime_instantiate");
  wasm_runtime_lookup_function = dlsym (cookie, "wasm_runtime_lookup_function");
  wasm_runtime_create_exec_env = dlsym (cookie, "wasm_runtime_create_exec_env");
  wasm_runtime_call_wasm = dlsym (cookie, "wasm_runtime_call_wasm");
  wasm_runtime_get_exception = dlsym (cookie, "wasm_runtime_get_exception");
  wasm_runtime_destroy_exec_env = dlsym (cookie, "wasm_runtime_destroy_exec_env");
  wasm_runtime_deinstantiate = dlsym (cookie, "wasm_runtime_deinstantiate");
  wasm_runtime_unload = dlsym (cookie, "wasm_runtime_unload");
  wasm_runtime_destroy = dlsym (cookie, "wasm_runtime_destroy");

  if (wasm_runtime_init == NULL || read_wasm_binary_to_buffer == NULL || wasm_runtime_load == NULL
      || wasm_runtime_instantiate == NULL || wasm_runtime_lookup_function == NULL || wasm_runtime_create_exec_env == NULL
      || wasm_runtime_call_wasm == NULL || wasm_runtime_get_exception == NULL || wasm_runtime_destroy_exec_env == NULL
      || wasm_runtime_deinstantiate == NULL || wasm_runtime_unload == NULL || wasm_runtime_destroy == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in `libiwasm.so`");


  int ret;
  char *buffer, error_buf[128];
  uint32_t size, stack_size = 8092, heap_size = 8092;

  /* initialize the wasm runtime by default configurations */
  wasm_runtime_init();

  /* read WASM file into a memory buffer */
  buffer = read_wasm_binary_to_buffer(pathname, &size);

  /* add line below if we want to export native functions to WASM app */
  // wasm_runtime_register_natives(...);

  /* parse the WASM file from buffer and create a WASM module */
  module = wasm_runtime_load(buffer, size, error_buf, sizeof(error_buf));

  /* create an instance of the WASM module (WASM linear memory is ready) */
  module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                         error_buf, sizeof(error_buf));

  /* lookup a WASM function by its name The function signature can NULL here */
  func = wasm_runtime_lookup_function(module_inst, "main");

  /* creat an execution environment to execute the WASM functions */
  exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);

  uint32_t num_args = 1, num_results = 1;
  wasm_val_t results[1];

  uint32_t argv2[2];

  /* arguments are always transferred in 32-bit element */
  argv2[0] = 8;

  /* call the WASM function */
  if (wasm_runtime_call_wasm(exec_env, func, 1, argv2) ) {
      /* the return value is stored in argv[0] */
      printf("fib function return: %d\n", argv2[0]);
  }
  else {
      /* exception is thrown if call fails */
      printf("%s\n", wasm_runtime_get_exception(module_inst));
  }

  wasm_runtime_destroy_exec_env(exec_env);
  wasm_runtime_deinstantiate(module_inst);
  wasm_runtime_unload(module);
  wasm_runtime_destroy();


  exit (EXIT_SUCCESS);
}

static int
wamr_can_handle_container (libcrun_container_t *container, libcrun_error_t *err)
{
  return wasm_can_handle_container (container, err);
}

// This works only when the plugin folder is present in /usr/lib/wasmedge
// static int
// libwamr_configure_container (void *cookie arg_unused, enum handler_configure_phase phase,
//                                  libcrun_context_t *context arg_unused, libcrun_container_t *container,
//                                  const char *rootfs arg_unused, libcrun_error_t *err)
// {
//   int ret;
//   runtime_spec_schema_config_schema *def = container->container_def;

//   if (getenv ("WASMEDGE_PLUGIN_PATH") == NULL && getenv ("WASMEDGE_WASINN_PRELOAD") == NULL)
//     return 0;

//   if (phase != HANDLER_CONFIGURE_AFTER_MOUNTS)
//     return 0;

//   // Check if /usr/lib/wasmedge is already present in spec
//   if (def->linux && def->mounts)
//     {
//       for (size_t i = 0; i < def->mounts_len; i++)
//         {
//           if (strcmp (def->mounts[i]->destination, "/usr/lib/wasmedge") == 0)
//             return 0;
//         }
//     }

//   // Mount the plugin folder to /usr/lib/wasmedge with specific options
//   char *options[] = {
//     "ro",
//     "rprivate",
//     "nosuid",
//     "nodev",
//     "rbind"
//   };

//   ret = libcrun_container_do_bind_mount (container, "/usr/lib/wasmedge ", "/usr/lib/wasmedge", options, 5, err);
//   if (ret < 0)
//     {
//       if (crun_error_get_errno (err) != ENOENT)
//         return ret;
//       crun_error_release (err);
//     }

//   return 0;
// }

struct custom_handler_s handler_wamr = {
  .name = "wamr",
  .alias = "wasm",
  .feature_string = "WASM:wamr",
  .load = libwamr_load,
  .unload = libwamr_unload,
  .run_func = libwamr_exec,
  .can_handle_container = wamr_can_handle_container,
  // .configure_container = libwamr_configure_container,
};

#endif