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
#  include <wasm.h>
#  include <wasi.h>
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
libwasmedge_unload (void *cookie, libcrun_error_t *err)
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

static int
libwasmedge_exec (void *cookie, __attribute__ ((unused)) libcrun_container_t *container, const char *pathname, char *const argv[])
{
//   WasmEdge_ConfigureContext *(*WasmEdge_ConfigureCreate) (void);
//   void (*WasmEdge_ConfigureDelete) (WasmEdge_ConfigureContext *Cxt);
//   void (*WasmEdge_ConfigureAddProposal) (WasmEdge_ConfigureContext *Cxt, const enum WasmEdge_Proposal Prop);
//   void (*WasmEdge_ConfigureAddHostRegistration) (WasmEdge_ConfigureContext *Cxt, enum WasmEdge_HostRegistration Host);
//   WasmEdge_VMContext *(*WasmEdge_VMCreate) (const WasmEdge_ConfigureContext *ConfCxt, WasmEdge_StoreContext *StoreCxt);
//   void (*WasmEdge_VMDelete) (WasmEdge_VMContext *Cxt);
//   WasmEdge_Result (*WasmEdge_VMRegisterModuleFromFile) (WasmEdge_VMContext *Cxt, WasmEdge_String ModuleName, const char *Path);
//   WasmEdge_Result (*WasmEdge_VMRunWasmFromFile) (WasmEdge_VMContext *Cxt, const char *Path, const WasmEdge_String FuncName, const WasmEdge_Value *Params, const uint32_t ParamLen, WasmEdge_Value *Returns, const uint32_t ReturnLen);
//   void (*WasmEdge_PluginLoadFromPath) (const char *Path);
//   void (*WasmEdge_PluginInitWASINN) (const char *const *NNPreloads, const uint32_t PreloadsLen);
//   bool (*WasmEdge_ResultOK) (const WasmEdge_Result Res);
//   WasmEdge_String (*WasmEdge_StringCreateByCString) (const char *Str);
//   uint32_t argn = 0;
//   uint32_t envn = 0;
//   const char *dirs[2] = { "/:/", ".:." };
//   WasmEdge_ConfigureContext *configure;
//   WasmEdge_VMContext *vm;
//   WasmEdge_Result result;

//   WasmEdge_ModuleInstanceContext *wasi_module;
//   WasmEdge_ModuleInstanceContext *(*WasmEdge_VMGetImportModuleContext) (WasmEdge_VMContext *Cxt, const enum WasmEdge_HostRegistration Reg);
//   void (*WasmEdge_ModuleInstanceInitWASI) (WasmEdge_ModuleInstanceContext *Cxt, const char *const *Args, const uint32_t ArgLen, const char *const *Envs, const uint32_t EnvLen, const char *const *Dirs, const uint32_t DirLen, const char *const *Preopens, const uint32_t PreopenLen);
//   WasmEdge_ModuleInstanceInitWASI = dlsym (cookie, "WasmEdge_ModuleInstanceInitWASI");

//   WasmEdge_ConfigureCreate = dlsym (cookie, "WasmEdge_ConfigureCreate");
//   WasmEdge_ConfigureDelete = dlsym (cookie, "WasmEdge_ConfigureDelete");
//   WasmEdge_ConfigureAddProposal = dlsym (cookie, "WasmEdge_ConfigureAddProposal");
//   WasmEdge_ConfigureAddHostRegistration = dlsym (cookie, "WasmEdge_ConfigureAddHostRegistration");
//   WasmEdge_VMCreate = dlsym (cookie, "WasmEdge_VMCreate");
//   WasmEdge_VMDelete = dlsym (cookie, "WasmEdge_VMDelete");
//   WasmEdge_VMRegisterModuleFromFile = dlsym (cookie, "WasmEdge_VMRegisterModuleFromFile");
//   WasmEdge_VMGetImportModuleContext = dlsym (cookie, "WasmEdge_VMGetImportModuleContext");
//   WasmEdge_VMRunWasmFromFile = dlsym (cookie, "WasmEdge_VMRunWasmFromFile");
//   WasmEdge_PluginLoadFromPath = dlsym (cookie, "WasmEdge_PluginLoadFromPath");
//   WasmEdge_PluginInitWASINN = dlsym (cookie, "WasmEdge_PluginInitWASINN");
//   WasmEdge_ResultOK = dlsym (cookie, "WasmEdge_ResultOK");
//   WasmEdge_StringCreateByCString = dlsym (cookie, "WasmEdge_StringCreateByCString");

//   if (WasmEdge_ConfigureCreate == NULL || WasmEdge_ConfigureDelete == NULL || WasmEdge_ConfigureAddProposal == NULL
//       || WasmEdge_ConfigureAddHostRegistration == NULL || WasmEdge_VMCreate == NULL || WasmEdge_VMDelete == NULL
//       || WasmEdge_VMRegisterModuleFromFile == NULL || WasmEdge_VMGetImportModuleContext == NULL
//       || WasmEdge_ModuleInstanceInitWASI == NULL || WasmEdge_VMRunWasmFromFile == NULL
//       || WasmEdge_ResultOK == NULL || WasmEdge_StringCreateByCString == NULL)
//     error (EXIT_FAILURE, 0, "could not find symbol in `libwasmedge.so.0`");

//   configure = WasmEdge_ConfigureCreate ();
//   if (UNLIKELY (configure == NULL))
//     error (EXIT_FAILURE, 0, "could not create wasmedge configure");

//   WasmEdge_ConfigureAddProposal (configure, WasmEdge_Proposal_BulkMemoryOperations);
//   WasmEdge_ConfigureAddProposal (configure, WasmEdge_Proposal_ReferenceTypes);
//   WasmEdge_ConfigureAddProposal (configure, WasmEdge_Proposal_SIMD);
//   WasmEdge_ConfigureAddHostRegistration (configure, WasmEdge_HostRegistration_Wasi);
//   // Check if the necessary environment variables are set
//   const char *plugin_path_env = getenv ("WASMEDGE_PLUGIN_PATH");
//   if (plugin_path_env != NULL)
//     WasmEdge_PluginLoadFromPath (plugin_path_env);

//   const char *nnpreload_env = getenv ("WASMEDGE_WASINN_PRELOAD");
//   if (nnpreload_env != NULL)
//     WasmEdge_PluginInitWASINN (&nnpreload_env, 1);

//   vm = WasmEdge_VMCreate (configure, NULL);
//   if (UNLIKELY (vm == NULL))
//     {
//       WasmEdge_ConfigureDelete (configure);
//       error (EXIT_FAILURE, 0, "could not create wasmedge vm");
//     }

//   wasi_module = WasmEdge_VMGetImportModuleContext (vm, WasmEdge_HostRegistration_Wasi);
//   if (UNLIKELY (wasi_module == NULL))
//     {
//       WasmEdge_VMDelete (vm);
//       WasmEdge_ConfigureDelete (configure);
//       error (EXIT_FAILURE, 0, "could not get wasmedge wasi module context");
//     }

//   for (char *const *arg = argv; *arg != NULL; ++arg, ++argn)
//     ;
//   extern char **environ;
//   for (char *const *env = environ; *env != NULL; ++env, ++envn)
//     ;

//   WasmEdge_ModuleInstanceInitWASI (wasi_module, (const char *const *) &argv[0], argn, (const char *const *) &environ[0], envn, dirs, 1, NULL, 0);

//   result = WasmEdge_VMRunWasmFromFile (vm, pathname, WasmEdge_StringCreateByCString ("_start"), NULL, 0, NULL, 0);

//   if (UNLIKELY (! WasmEdge_ResultOK (result)))
//     {
//       WasmEdge_VMDelete (vm);
//       WasmEdge_ConfigureDelete (configure);
//       error (EXIT_FAILURE, 0, "could not get wasmedge result from VM");
//     }

//   WasmEdge_VMDelete (vm);
//   WasmEdge_ConfigureDelete (configure);

  int ret;
  char *buffer, error_buf[128];
  wasm_module_t module;
  wasm_module_inst_t module_inst;
  wasm_function_inst_t func;
  wasm_exec_env_t exec_env;
  uint32 size, stack_size = 8092, heap_size = 8092;

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

  uint32 num_args = 1, num_results = 1;
  wasm_val_t results[1];

  uint32 argv[2];

  /* arguments are always transferred in 32-bit element */
  argv[0] = 8;

  /* call the WASM function */
  if (wasm_runtime_call_wasm(exec_env, func, 1, argv) ) {
      /* the return value is stored in argv[0] */
      printf("fib function return: %d\n", argv[0]);
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
wasmedge_can_handle_container (libcrun_container_t *container, libcrun_error_t *err)
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
  .unload = libwasmr_unload,
  .run_func = libwamr_exec,
  .can_handle_container = wamr_can_handle_container,
  // .configure_container = libwamr_configure_container,
};

#endif