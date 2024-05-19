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
#include <time.h>

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
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0001 libwamr_load:start id=", "a", ts);
  void *handle;

  handle = dlopen ("libiwasm.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libiwasm.so`: `%s`", dlerror ());
  *cookie = handle;

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0002 libwamr_load:done id=", "a", ts);

  return 0;
}

static int
libwamr_unload (void *cookie, libcrun_error_t *err)
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0003 libwamr_unload:start id=", "a", ts);
  int r;

  if (cookie)
    {
      r = dlclose (cookie);
      if (UNLIKELY (r < 0))
        return crun_make_error (err, 0, "could not unload handle: `%s`", dlerror ());
    }
  
  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0004 libwamr_unload:done id=", "a", ts);
  return 0;
}

// Function to read a WebAssembly binary file into a buffer
char *read_wasm_binary_to_buffer(const char *pathname, uint32_t *size) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0005 read_wasm_binary_to_buffer:start pathname=", pathname, ts);

    FILE *file;
    char *buffer;
    size_t file_size;

    // Open the file in binary mode
    file = fopen(pathname, "rb");
    if (!file) {
        error (EXIT_FAILURE, 0, "Failed to open file");
        return NULL;
    }

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0006 read_wasm_binary_to_buffer:fopen:done id=", "a", ts);

    // Seek to the end of the file to determine the size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

  clock_gettime(CLOCK_REALTIME, &ts);
  char str[500];
  sprintf(str, "%ld", file_size);
  log_message("[CONTINUUM]2 0007 read_wasm_binary_to_buffer:fseek:done size=", str, ts);

    // Allocate memory for the buffer
    buffer = (char *)malloc(file_size);
    if (!buffer) {
        error (EXIT_FAILURE, 0, "Failed to allocate memory");
        fclose(file);
        return NULL;
    }

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0008 read_wasm_binary_to_buffer:malloc:done id=", "a", ts);

    // Read the file into the buffer
    if (fread(buffer, 1, file_size, file) != file_size) {
        error (EXIT_FAILURE, 0, "Failed to read file");
        free(buffer);
        fclose(file);
        return NULL;
    }

  clock_gettime(CLOCK_REALTIME, &ts);
  //get size of the full buffer
  log_message("[CONTINUUM]2 0009 read_wasm_binary_to_buffer:fread:done id=", "a", ts);

    // Close the file
    fclose(file);

    // Set the size output parameter
    *size = file_size;

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0010 read_wasm_binary_to_buffer:done id=", "a", ts);

    // Return the buffer
    return buffer;
}

static int
libwamr_exec (void *cookie, __attribute__ ((unused)) libcrun_container_t *container, const char *pathname, char *const argv[])
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0011 libwamr_exec:start id=", "a", ts);

  // load symbols from the shared library libiwasm.so
  bool (*wasm_runtime_init) ();
  RuntimeInitArgs init_args;
  bool (*wasm_runtime_full_init)(RuntimeInitArgs *init_args);
  wasm_module_t module;
  wasm_module_t (*wasm_runtime_load) (uint8_t *buf, uint32_t size, char *error_buf, uint32_t error_buf_size);
  wasm_module_inst_t module_inst;
  wasm_module_inst_t (*wasm_runtime_instantiate) (const wasm_module_t module, uint32_t default_stack_size, uint32_t host_managed_heap_size, char *error_buf, uint32_t error_buf_size);
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
  uint32_t (*wasm_runtime_get_wasi_exit_code)(wasm_module_inst_t module_inst);
  bool (*wasm_application_execute_main)(wasm_module_inst_t module_inst, int32_t argc, char *argv[]);

  wasm_runtime_init = dlsym (cookie, "wasm_runtime_init");
  wasm_runtime_full_init = dlsym (cookie, "wasm_runtime_full_init");
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
  wasm_runtime_get_wasi_exit_code = dlsym (cookie, "wasm_runtime_get_wasi_exit_code");
  wasm_application_execute_main = dlsym (cookie, "wasm_application_execute_main");

  if (wasm_runtime_init == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_init symbol in `libiwasm.so`");
  if(wasm_runtime_full_init == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_full_init symbol in `libiwasm.so`");
  if (wasm_runtime_load == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_load symbol in `libiwasm.so`");
  if (wasm_runtime_instantiate == NULL) 
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_instantiate symbol in `libiwasm.so`");
  if (wasm_runtime_lookup_function == NULL)
    error (EXIT_FAILURE, 0, "could not find  wasm_runtime_lookup_functionsymbol in `libiwasm.so`");
  if (wasm_runtime_create_exec_env == NULL)
    error (EXIT_FAILURE, 0, "could not find  wasm_runtime_create_exec_env symbol in `libiwasm.so`");
  if (wasm_runtime_call_wasm == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_call_wasm symbol in `libiwasm.so`");
  if (wasm_runtime_get_exception == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_get_exception symbol in `libiwasm.so`");
  if (wasm_runtime_destroy_exec_env == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_destroy_exec_env symbol in `libiwasm.so`");
  if (wasm_runtime_deinstantiate == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_deinstantiate symbol in `libiwasm.so`");
  if (wasm_runtime_unload == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_unload symbol in `libiwasm.so`");
  if (wasm_runtime_destroy == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_destroy symbol in `libiwasm.so`");
  if (wasm_runtime_get_wasi_exit_code == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_runtime_get_wasi_exit_code symbol in `libiwasm.so`");
  if (wasm_application_execute_main == NULL)
    error (EXIT_FAILURE, 0, "could not find wasm_application_execute_main symbol in `libiwasm.so`");

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0012 libwamr_exec:so:load:done id=", "a", ts);

  static char global_heap_buf[256 * 1024];
  int ret;
  char *buffer, error_buf[128];
  uint32_t size, stack_size = 8096, heap_size = 8096;

  memset(&init_args, 0, sizeof(RuntimeInitArgs));
  /* initialize the wasm runtime by default configurations */
  // if(!wasm_runtime_init()) {
  //   clock_gettime(CLOCK_REALTIME, &ts);
  //   log_message("[CONTINUUM]2 0013 libwamr_exec:wasm_runtime_init:error id=", "error", ts);
  // }

  init_args.mem_alloc_type = Alloc_With_Allocator;
  init_args.mem_alloc_option.allocator.malloc_func = malloc;
  init_args.mem_alloc_option.allocator.realloc_func = realloc;
  init_args.mem_alloc_option.allocator.free_func = free;

  // init_args.mem_alloc_type = Alloc_With_Pool;
  // init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
  // init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

  // /* initialize runtime environment */
  if (!wasm_runtime_full_init(&init_args)) {
    clock_gettime(CLOCK_REALTIME, &ts);
    log_message("[CONTINUUM]2 0013 libwamr_exec:wasm_runtime_init:error id=", "error", ts);
  }

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0013 libwamr_exec:wasm_runtime_init:done id=", "none", ts);

  /* read WASM file into a memory buffer */
  buffer = read_wasm_binary_to_buffer(pathname, &size);

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0014 libwamr_exec:read_wasm_binary_to_buffer:done id=", "none", ts);

  /* add line below if we want to export native functions to WASM app */
  // wasm_runtime_register_natives(...);

  /* parse the WASM file from buffer and create a WASM module */
  module = wasm_runtime_load(buffer, size, error_buf, sizeof(error_buf));

  if (!module) {
    clock_gettime(CLOCK_REALTIME, &ts);
    log_message("[CONTINUUM]2 0025 libwamr_exec:wasm_runtime_load:error id=", error_buf, ts);
  }

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0015 libwamr_exec:wasm_runtime_load:done id=", "none", ts);

  /* create an instance of the WASM module (WASM linear memory is ready) */
  module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                         error_buf, sizeof(error_buf));

  if (!module_inst) {
    clock_gettime(CLOCK_REALTIME, &ts);
    log_message("[CONTINUUM]2 0026 libwamr_exec:wasm_runtime_instantiate:error id=", error_buf, ts);
  }

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0016 libwamr_exec:wasm_runtime_instantiate:done id=", "none", ts);

  /* lookup a WASM function by its name The function signature can NULL here */
  // func = wasm_runtime_lookup_function(module_inst, "add");

  // if (!func || func == NULL) {
  //   clock_gettime(CLOCK_REALTIME, &ts);
  //   log_message("[CONTINUUM]2 0027 libwamr_exec:wasm_runtime_lookup_function:error id=", "error", ts);
  // }

  // clock_gettime(CLOCK_REALTIME, &ts);
  // log_message("[CONTINUUM]2 0017 libwamr_exec:wasm_runtime_lookup_function:done id=", func, ts);

  /* creat an execution environment to execute the WASM functions */
  exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0018 libwamr_exec:wasm_runtime_create_exec_env:done id=", "a", ts);

  uint32_t num_args = 1, num_results = 1;
  wasm_val_t results[1];

  // uint32_t argv2[2];
  uint32_t result;

  /* arguments are always transferred in 32-bit element */
  // argv2[0] = 8;

  /* call the WASM function */
  if (wasm_application_execute_main(module_inst, 0, NULL) ) {
      /* the return value is stored in argv[0] */
      result = wasm_runtime_get_wasi_exit_code(module_inst);
      printf("fib function return: %d\n", result);
      clock_gettime(CLOCK_REALTIME, &ts);
      log_message("[CONTINUUM]2 0019 libwamr_exec:wasm_runtime_call_wasm:done id=", result, ts);
  }
  else {
      /* exception is thrown if call fails */
      clock_gettime(CLOCK_REALTIME, &ts);
      log_message("[CONTINUUM]2 0019 libwamr_exec:wasm_runtime_call_wasm:error id=", wasm_runtime_get_exception(module_inst), ts);
  }

  wasm_runtime_destroy_exec_env(exec_env);

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0020 libwamr_exec:wasm_runtime_destroy_exec_env:done id=", "a", ts);

  wasm_runtime_deinstantiate(module_inst);

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0021 libwamr_exec:wasm_runtime_deinstantiate:done id=", "a", ts);

  wasm_runtime_unload(module);

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0022 libwamr_exec:wasm_runtime_unload:done id=", "a", ts);

  wasm_runtime_destroy();

  clock_gettime(CLOCK_REALTIME, &ts);
  log_message("[CONTINUUM]2 0023 libwamr_exec:done id=", "a", ts);

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