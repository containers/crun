/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2024 Maciej Kozub <maciej@kozub.work>
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

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_WAMR
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
char *
read_wasm_binary_to_buffer (const char *pathname, uint32_t *size)
{

  FILE *file;
  char *buffer;
  size_t file_size;

  // Open the file in binary mode
  file = fopen (pathname, "rb");
  if (! file)
    {
      error (EXIT_FAILURE, 0, "Failed to open file");
      return NULL;
    }

  // Seek to the end of the file to determine the size
  fseek (file, 0, SEEK_END);
  file_size = ftell (file);
  fseek (file, 0, SEEK_SET);

  // Allocate memory for the buffer
  buffer = (char *) malloc (file_size);
  if (! buffer)
    {
      error (EXIT_FAILURE, 0, "Failed to allocate memory");
      fclose (file);
      return NULL;
    }

  // Read the file into the buffer
  if (fread (buffer, 1, file_size, file) != file_size)
    {
      error (EXIT_FAILURE, 0, "Failed to read file");
      free (buffer);
      fclose (file);
      return NULL;
    }
  // Close the file
  fclose (file);

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
  RuntimeInitArgs init_args;
  wasm_module_t module;
  wasm_module_t (*wasm_runtime_load) (uint8_t * buf, uint32_t size, char *error_buf, uint32_t error_buf_size);
  wasm_module_inst_t module_inst;
  wasm_module_inst_t (*wasm_runtime_instantiate) (const wasm_module_t module, uint32_t default_stack_size, uint32_t host_managed_heap_size, char *error_buf, uint32_t error_buf_size);
  wasm_function_inst_t func;
  wasm_function_inst_t (*wasm_runtime_lookup_function) (wasm_module_inst_t const module_inst, const char *name);
  wasm_exec_env_t exec_env;
  wasm_exec_env_t (*wasm_runtime_create_exec_env) (wasm_module_inst_t module_inst, uint32_t stack_size);
  bool (*wasm_runtime_call_wasm) (wasm_exec_env_t exec_env, wasm_function_inst_t function, uint32_t argc, uint32_t argv[]);
  void (*wasm_runtime_destroy_exec_env) (wasm_exec_env_t exec_env);
  void (*wasm_runtime_deinstantiate) (wasm_module_inst_t module_inst);
  void (*wasm_runtime_unload) (wasm_module_t module);
  void (*wasm_runtime_destroy) ();
  void (*wasm_runtime_set_wasi_args) (wasm_module_t module, const char *dir_list[], uint32_t dir_count, const char *map_dir_list[], uint32_t map_dir_count, const char *env[], uint32_t env_count, char *argv[], int argc);

  wasm_runtime_init = dlsym (cookie, "wasm_runtime_init");
  wasm_runtime_load = dlsym (cookie, "wasm_runtime_load");
  wasm_runtime_instantiate = dlsym (cookie, "wasm_runtime_instantiate");
  wasm_runtime_lookup_function = dlsym (cookie, "wasm_runtime_lookup_function");
  wasm_runtime_create_exec_env = dlsym (cookie, "wasm_runtime_create_exec_env");
  wasm_runtime_call_wasm = dlsym (cookie, "wasm_runtime_call_wasm");
  wasm_runtime_destroy_exec_env = dlsym (cookie, "wasm_runtime_destroy_exec_env");
  wasm_runtime_deinstantiate = dlsym (cookie, "wasm_runtime_deinstantiate");
  wasm_runtime_unload = dlsym (cookie, "wasm_runtime_unload");
  wasm_runtime_destroy = dlsym (cookie, "wasm_runtime_destroy");
  wasm_runtime_set_wasi_args = dlsym (cookie, "wasm_runtime_set_wasi_args");

  if (wasm_runtime_init == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_init symbol in `libiwasm.so`");
  if (wasm_runtime_load == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_load symbol in `libiwasm.so`");
  if (wasm_runtime_instantiate == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_instantiate symbol in `libiwasm.so`");
  if (wasm_runtime_lookup_function == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_lookup_function symbol in `libiwasm.so`");
  if (wasm_runtime_create_exec_env == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_create_exec_env symbol in `libiwasm.so`");
  if (wasm_runtime_call_wasm == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_call_wasm symbol in `libiwasm.so`");
  if (wasm_runtime_destroy_exec_env == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_destroy_exec_env symbol in `libiwasm.so`");
  if (wasm_runtime_deinstantiate == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_deinstantiate symbol in `libiwasm.so`");
  if (wasm_runtime_unload == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_unload symbol in `libiwasm.so`");
  if (wasm_runtime_destroy == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_destroy symbol in `libiwasm.so`");
  if (wasm_runtime_set_wasi_args == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_set_wasi_args symbol in `libiwasm.so`");

  char *buffer, error_buf[128];
  uint32_t buffer_size, stack_size = 8096, heap_size = 8096;

  const char *dirs[2] = { "/", "." };
  char **container_env = container->container_def->process->env;
  size_t env_count = container->container_def->process->env_len;

  int arg_count = 0;
  char *const *arg;
  for (arg = argv; *arg != NULL; ++arg)
    arg_count++;

  /* initialize the wasm runtime by default configurations */
  if (! wasm_runtime_init ())
    error (EXIT_FAILURE, 0, "Failed to initialize the wasm runtime");

  /* read WASM file into a memory buffer */
  buffer = read_wasm_binary_to_buffer (pathname, &buffer_size);
  if (! buffer || buffer_size == 0)
    error (EXIT_FAILURE, 0, "Failed to read file");

  /* parse the WASM file from buffer and create a WASM module */
  module = wasm_runtime_load (buffer, buffer_size, error_buf, sizeof (error_buf));
  if (! module)
    error (EXIT_FAILURE, 0, "Failed to load WASM file");

  /* instantiate the WASI environment */
  wasm_runtime_set_wasi_args (module, dirs, 1, NULL, 0, container_env, env_count, (char **) argv, arg_count);

  /* create an instance of the WASM module (WASM linear memory is ready) */
  module_inst = wasm_runtime_instantiate (module, stack_size, heap_size, error_buf, sizeof (error_buf));
  if (! module_inst)
    error (EXIT_FAILURE, 0, "Failed to instantiate the WASM module");

  /* lookup a WASM function by its name; the function signature can be NULL here */
  func = wasm_runtime_lookup_function (module_inst, "_start");
  if (! func || func == NULL)
    error (EXIT_FAILURE, 0, "Failed to lookup the WASM function");

  /* creat an execution environment to execute the WASM functions */
  exec_env = wasm_runtime_create_exec_env (module_inst, stack_size);
  if (! exec_env)
    error (EXIT_FAILURE, 0, "Failed to create the execution environment");

  /* call the WASM function */
  if (! wasm_runtime_call_wasm (exec_env, func, 0, NULL))
    error (EXIT_FAILURE, 0, "Failed to call the WASM function");

  wasm_runtime_destroy_exec_env (exec_env);
  wasm_runtime_deinstantiate (module_inst);
  wasm_runtime_unload (module);
  wasm_runtime_destroy ();

  exit (EXIT_SUCCESS);
}

static int
wamr_can_handle_container (libcrun_container_t *container, libcrun_error_t *err)
{
  return wasm_can_handle_container (container, err);
}

struct custom_handler_s handler_wamr = {
  .name = "wamr",
  .alias = "wasm",
  .feature_string = "WASM:wamr",
  .load = libwamr_load,
  .unload = libwamr_unload,
  .run_func = libwamr_exec,
  .can_handle_container = wamr_can_handle_container,
};

#endif
