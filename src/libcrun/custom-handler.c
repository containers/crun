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
#include "custom-handler.h"
#include "container.h"
#include "utils.h"
#include "linux.h"
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_LIBKRUN
#  include <libkrun.h>
#endif

#ifdef HAVE_WASMER
#  include <wasmer.h>
#endif

#ifdef HAVE_WASMEDGE
#  include <wasmedge/wasmedge.h>
#endif

#if HAVE_DLOPEN && HAVE_WASMER
#  define WASMER_BUF_SIZE 128
static int
libwasmer_exec (void *cookie, libcrun_container_t *container, const char *pathname, char *const argv[])
{
  int ret;
  char buffer[WASMER_BUF_SIZE] = { 0 };
  size_t data_read_size = WASMER_BUF_SIZE;
  const wasm_func_t *core_func;
  FILE *wat_wasm_file;
  size_t file_size;
  void *handle = arg;
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
  void (*wasi_config_arg) (struct wasi_config_t * config, const char *arg);

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
    error (EXIT_FAILURE, -1, "error compiling wasm module");

  wasi_config_t *config = wasi_config_new ("crun_wasi_program");

  /* Count number of external arguments given.  */
  for (char *const *arg = argv; *arg != NULL; ++arg)
    args_size++;

  if (args_size > 1)
    {
      wasi_args = str_join_array (1, args_size, argv, " ");
      wasi_config_arg (config, wasi_args);
    }

  wasi_config_capture_stdout (config);
  wasi_env_t *wasi_env = wasi_env_new (config);
  if (! wasi_env)
    {
      error (EXIT_FAILURE, -1, "error building wasi env");
    }

  /* Instantiate.  */
  wasm_importtype_vec_t import_types;
  wasm_module_imports (module, &import_types);

  wasm_extern_vec_t imports;
  wasm_extern_vec_new_uninitialized (&imports, import_types.size);
  wasm_importtype_vec_delete (&import_types);

  bool get_imports_result = wasi_get_imports (store, module, wasi_env, &imports);

  if (! get_imports_result)
    error (EXIT_FAILURE, -1, "error getting WASI imports");

  instance = wasm_instance_new (store, module, &imports, NULL);

  if (! instance)
    error (EXIT_FAILURE, -1, "error instantiating module");

  /* Extract export.  */
  wasm_instance_exports (instance, &exports);
  if (exports.size == 0)
    error (EXIT_FAILURE, -1, "error getting instance exports");

  wasm_func_t *run_func = wasi_get_start_function (instance);
  if (run_func == NULL)
    error (EXIT_FAILURE, -1, "error accessing export");

  wasm_module_delete (module);
  wasm_instance_delete (instance);
  wasm_val_vec_t args = WASM_EMPTY_VEC;
  wasm_val_vec_t res = WASM_EMPTY_VEC;

  if (wasm_func_call (run_func, &args, &res))
    error (EXIT_FAILURE, -1, "error calling wasm function");

  {
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
  }

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
libwasmer_load (struct custom_handler_s *out, libcrun_error_t *err)
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
  const char *annotation;

  annotation = find_annotation (container, "module.wasm.image/variant");
  if (! annotation)
    return 0;

  return strcmp (annotation, "compat") == 0 ? 1 : 0;
}

static struct custom_handler_s wasmer_handler = {
  .name = "wasmer",
  .feature_string = "WASM:wasmer",
  .load = libwasmer_load,
  .unload = libwasmer_unload,
  .exec_func = libwasmer_exec,
  .can_handle_container = libwasmer_can_handle_container,
};
#endif

/* libkrun handler.  */
#if HAVE_DLOPEN && HAVE_LIBKRUN
static int
libkrun_exec (void *cookie, libcrun_container_t *container, const char *pathname, char *const argv[])
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int32_t (*krun_create_ctx) ();
  int (*krun_start_enter) (uint32_t ctx_id);
  int32_t (*krun_set_vm_config) (uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);
  int32_t (*krun_set_root) (uint32_t ctx_id, const char *root_path);
  int32_t (*krun_set_workdir) (uint32_t ctx_id, const char *workdir_path);
  int32_t (*krun_set_exec) (uint32_t ctx_id, const char *exec_path, char *const argv[], char *const envp[]);
  void *handle = cookie;
  uint32_t num_vcpus, ram_mib;
  int32_t ctx_id, ret;
  cpu_set_t set;

  krun_create_ctx = dlsym (handle, "krun_create_ctx");
  krun_start_enter = dlsym (handle, "krun_start_enter");
  krun_set_vm_config = dlsym (handle, "krun_set_vm_config");
  krun_set_root = dlsym (handle, "krun_set_root");
  krun_set_workdir = dlsym (handle, "krun_set_workdir");
  krun_set_exec = dlsym (handle, "krun_set_exec");
  if (krun_create_ctx == NULL || krun_start_enter == NULL
      || krun_set_vm_config == NULL || krun_set_root == NULL
      || krun_set_exec == NULL)
      error (EXIT_FAILURE, 0,"could not find symbol in `libkrun.so`");

  /* If sched_getaffinity fails, default to 1 vcpu.  */
  num_vcpus = 1;
  /* If no memory limit is specified, default to 2G.  */
  ram_mib = 2 * 1024;

  if (def && def->linux && def->linux->resources && def->linux->resources->memory
      && def->linux->resources->memory->limit_present)
    ram_mib = def->linux->resources->memory->limit / (1024 * 1024);

  CPU_ZERO (&set);
  if (sched_getaffinity (getpid (), sizeof (set), &set) == 0)
    num_vcpus = CPU_COUNT (&set);

  ctx_id = krun_create_ctx ();
  if (UNLIKELY (ctx_id < 0))
    error (EXIT_FAILURE, -ret, "could not create krun context");

  ret = krun_set_vm_config (ctx_id, num_vcpus, ram_mib);
  if (UNLIKELY (ret < 0))
    error (EXIT_FAILURE, -ret, "could not set krun vm configuration");

  ret = krun_set_root (ctx_id, "/");
  if (UNLIKELY (ret < 0))
    error (EXIT_FAILURE, -ret, "could not set krun root");

  if (krun_set_workdir && def && def->process && def->process->cwd)
    {
      ret = krun_set_workdir (ctx_id, def->process->cwd);
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set krun working directory");
    }

  ret = krun_set_exec (ctx_id, pathname, &argv[1], NULL);
  if (UNLIKELY (ret < 0))
    error (EXIT_FAILURE, -ret, "could not set krun executable");

  return krun_start_enter (ctx_id);
}

/* libkrun_create_kvm_device: explicitly adds kvm device.  */
static int
libkrun_configure_container (void *cookie arg_unused, enum handler_configure_phase phase,
                             libcrun_context_t *context, libcrun_container_t *container,
                             const char *rootfs, libcrun_error_t *err)
{
  int ret, rootfsfd;
  size_t i;
  struct device_s kvm_device = { "/dev/kvm", "c", 10, 232, 0666, 0, 0 };
  cleanup_close int devfd = -1;
  cleanup_close int rootfsfd_cleanup = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  bool is_user_ns;

  if (phase != HANDLER_CONFIGURE_AFTER_MOUNTS)
    return 0;

  /* Do nothing if /dev/kvm is already present in spec */
  for (i = 0; i < def->linux->devices_len; i++)
    {
      if (strcmp (def->linux->devices[i]->path, "/dev/kvm") == 0)
        return 0;
    }

  if (rootfs == NULL)
    rootfsfd = AT_FDCWD;
  else
    {
      rootfsfd = rootfsfd_cleanup = open (rootfs, O_PATH);
      if (UNLIKELY (rootfsfd < 0))
        return crun_make_error (err, errno, "open `%s`", rootfs);
    }

  devfd = openat (rootfsfd, "dev", O_RDONLY | O_DIRECTORY);
  if (UNLIKELY (devfd < 0))
    return crun_make_error (err, errno, "open /dev directory in `%s`", rootfs);

  ret = check_running_in_user_namespace (err);
  if (UNLIKELY (ret < 0))
    return ret;
  is_user_ns = ret;

  ret = libcrun_create_dev (container, devfd, &kvm_device, is_user_ns, true, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
libkrun_load (void **cookie, libcrun_error_t *err arg_unused)
{
  void *handle;

  handle = dlopen ("libkrun.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libkrun.so`: %s", dlerror ());

  *cookie = handle;

  return 0;
}

static int
libkrun_unload (void *cookie, libcrun_error_t *err arg_unused)
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

static struct custom_handler_s libkrun_handler = {
  .name = "krun",
  .feature_string = "LIBKRUN",
  .load = libkrun_load,
  .unload = libkrun_unload,
  .exec_func = libkrun_exec,
  .configure_container = libkrun_configure_container,
};
#endif

#if HAVE_DLOPEN && HAVE_WASMEDGE
static int
libwasmedge_load (void **cookie, libcrun_error_t *err arg_unused)
{
  void *handle;

  handle = dlopen ("libwasmedge_c.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libwasmedge_c.so`: %s", dlerror ());
  *cookie = handle;

  return 0;
}

static int
libwasmedge_unload (void *cookie, libcrun_error_t *err arg_unused)
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
libwasmedge_exec (void *cookie, libcrun_container_t *container, const char *pathname, char *const argv[])
{
  runtime_spec_schema_config_schema *def = container->container_def;
  WasmEdge_ConfigureContext *(*WasmEdge_ConfigureCreate) (void);
  void (*WasmEdge_ConfigureDelete) (WasmEdge_ConfigureContext * Cxt);
  void (*WasmEdge_ConfigureAddProposal) (WasmEdge_ConfigureContext * Cxt, const enum WasmEdge_Proposal Prop);
  void (*WasmEdge_ConfigureAddHostRegistration) (WasmEdge_ConfigureContext * Cxt, enum WasmEdge_HostRegistration Host);
  WasmEdge_VMContext *(*WasmEdge_VMCreate) (const WasmEdge_ConfigureContext *ConfCxt, WasmEdge_StoreContext *StoreCxt);
  void (*WasmEdge_VMDelete) (WasmEdge_VMContext * Cxt);
  WasmEdge_Result (*WasmEdge_VMRegisterModuleFromFile) (WasmEdge_VMContext * Cxt, WasmEdge_String ModuleName, const char *Path);
  WasmEdge_ImportObjectContext *(*WasmEdge_VMGetImportModuleContext) (WasmEdge_VMContext * Cxt, const enum WasmEdge_HostRegistration Reg);
  void (*WasmEdge_ImportObjectInitWASI) (WasmEdge_ImportObjectContext * Cxt, const char *const *Args, const uint32_t ArgLen, const char *const *Envs, const uint32_t EnvLen, const char *const *Dirs, const uint32_t DirLen, const char *const *Preopens, const uint32_t PreopenLen);
  void (*WasmEdge_ImportObjectInitWasmEdgeProcess) (WasmEdge_ImportObjectContext * Cxt, const char *const *AllowedCmds, const uint32_t CmdsLen, const bool AllowAll);
  WasmEdge_Result (*WasmEdge_VMRunWasmFromFile) (WasmEdge_VMContext * Cxt, const char *Path, const WasmEdge_String FuncName, const WasmEdge_Value *Params, const uint32_t ParamLen, WasmEdge_Value *Returns, const uint32_t ReturnLen);
  bool (*WasmEdge_ResultOK) (const WasmEdge_Result Res);
  WasmEdge_String (*WasmEdge_StringCreateByCString) (const char *Str);
  uint32_t argn = 0;
  const char *dirs[1] = { "/:/" };
  WasmEdge_ConfigureContext *configure;
  WasmEdge_VMContext *vm;
  WasmEdge_ImportObjectContext *wasi_module;
  WasmEdge_ImportObjectContext *proc_module;
  WasmEdge_Result result;

  WasmEdge_ConfigureCreate = dlsym (cookie, "WasmEdge_ConfigureCreate");
  WasmEdge_ConfigureDelete = dlsym (cookie, "WasmEdge_ConfigureDelete");
  WasmEdge_ConfigureAddProposal = dlsym (cookie, "WasmEdge_ConfigureAddProposal");
  WasmEdge_ConfigureAddHostRegistration = dlsym (cookie, "WasmEdge_ConfigureAddHostRegistration");
  WasmEdge_VMCreate = dlsym (cookie, "WasmEdge_VMCreate");
  WasmEdge_VMDelete = dlsym (cookie, "WasmEdge_VMDelete");
  WasmEdge_VMRegisterModuleFromFile = dlsym (cookie, "WasmEdge_VMRegisterModuleFromFile");
  WasmEdge_VMGetImportModuleContext = dlsym (cookie, "WasmEdge_VMGetImportModuleContext");
  WasmEdge_ImportObjectInitWASI = dlsym (cookie, "WasmEdge_ImportObjectInitWASI");
  WasmEdge_ImportObjectInitWasmEdgeProcess = dlsym (cookie, "WasmEdge_ImportObjectInitWasmEdgeProcess");
  WasmEdge_VMRunWasmFromFile = dlsym (cookie, "WasmEdge_VMRunWasmFromFile");
  WasmEdge_ResultOK = dlsym (cookie, "WasmEdge_ResultOK");
  WasmEdge_StringCreateByCString = dlsym (cookie, "WasmEdge_StringCreateByCString");

  if (WasmEdge_ConfigureCreate == NULL || WasmEdge_ConfigureDelete == NULL || WasmEdge_ConfigureAddProposal == NULL
      || WasmEdge_ConfigureAddHostRegistration == NULL || WasmEdge_VMCreate == NULL || WasmEdge_VMDelete == NULL
      || WasmEdge_VMRegisterModuleFromFile == NULL || WasmEdge_VMGetImportModuleContext == NULL || WasmEdge_ImportObjectInitWASI == NULL
      || WasmEdge_ImportObjectInitWasmEdgeProcess == NULL || WasmEdge_VMRunWasmFromFile == NULL || WasmEdge_ResultOK == NULL
      || WasmEdge_StringCreateByCString == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in `libwasmedge.so`");

  configure = WasmEdge_ConfigureCreate ();
  if (UNLIKELY (configure == NULL))
    error (EXIT_FAILURE, 0, "could not create wasmedge configure");

  WasmEdge_ConfigureAddProposal (configure, WasmEdge_Proposal_BulkMemoryOperations);
  WasmEdge_ConfigureAddProposal (configure, WasmEdge_Proposal_ReferenceTypes);
  WasmEdge_ConfigureAddProposal (configure, WasmEdge_Proposal_SIMD);
  WasmEdge_ConfigureAddHostRegistration (configure, WasmEdge_HostRegistration_Wasi);
  WasmEdge_ConfigureAddHostRegistration (configure, WasmEdge_HostRegistration_WasmEdge_Process);

  vm = WasmEdge_VMCreate (configure, NULL);
  if (UNLIKELY (vm == NULL))
    {
      WasmEdge_ConfigureDelete (configure);
      error (EXIT_FAILURE, 0, "could not create wasmedge vm");
    }

  wasi_module = WasmEdge_VMGetImportModuleContext (vm, WasmEdge_HostRegistration_Wasi);
  if (UNLIKELY (wasi_module == NULL))
    {
      WasmEdge_VMDelete (vm);
      WasmEdge_ConfigureDelete (configure);
      error (EXIT_FAILURE, 0, "could not get wasmedge wasi module context");
    }

  proc_module = WasmEdge_VMGetImportModuleContext (vm, WasmEdge_HostRegistration_WasmEdge_Process);
  if (UNLIKELY (proc_module == NULL))
    {
      WasmEdge_VMDelete (vm);
      WasmEdge_ConfigureDelete (configure);
      error (EXIT_FAILURE, 0, "could not get wasmedge process module context");
    }

  for (char *const *arg = argv; *arg != NULL; ++arg, ++argn)
    ;

  WasmEdge_ImportObjectInitWASI (wasi_module, (const char *const *) &argv[0], argn, NULL, 0, dirs, 1, NULL, 0);

  WasmEdge_ImportObjectInitWasmEdgeProcess (proc_module, NULL, 0, true);

  result = WasmEdge_VMRunWasmFromFile (vm, pathname, WasmEdge_StringCreateByCString ("_start"), NULL, 0, NULL, 0);

  if (UNLIKELY (! WasmEdge_ResultOK (result)))
    {
      WasmEdge_VMDelete (vm);
      WasmEdge_ConfigureDelete (configure);
      error (EXIT_FAILURE, 0, "could not get wasmedge result from VM");
    }

  WasmEdge_VMDelete (vm);
  WasmEdge_ConfigureDelete (configure);
  exit (EXIT_SUCCESS);
}

static int
wasmedge_can_handle_container (libcrun_container_t *container, libcrun_error_t *err arg_unused)
{
  const char *annotation;

  annotation = find_annotation (container, "module.wasm.image/variant");
  if (! annotation)
    return 0;

  return strcmp (annotation, "compat") == 0 ? 1 : 0;
}

static struct custom_handler_s wasmedge_handler = {
  .name = "wasmedge",
  .feature_string = "WASM:wasmedge",
  .load = libwasmedge_load,
  .unload = libwasmedge_unload,
  .exec_func = libwasmedge_exec,
  .can_handle_container = wasmedge_can_handle_container,
};
#endif

static struct custom_handler_s *static_handlers[] = {
#if HAVE_DLOPEN && HAVE_LIBKRUN
  &libkrun_handler,
#endif
#if HAVE_DLOPEN && HAVE_WASMEDGE
  &wasmedge_handler,
#endif
#if HAVE_DLOPEN && HAVE_WASMER
  &wasmer_handler,
#endif
  NULL,
};

struct custom_handler_manager_s
{
  struct custom_handler_s **handlers;
};

struct custom_handler_manager_s *
handler_manager_create (libcrun_error_t *err arg_unused)
{
  struct custom_handler_manager_s *m;

  m = xmalloc0 (sizeof (struct custom_handler_manager_s));
  m->handlers = static_handlers;
  return m;
}

void
handler_manager_free (struct custom_handler_manager_s *manager)
{
  free (manager);
}

struct custom_handler_s *
handler_by_name (struct custom_handler_manager_s *manager, const char *name)
{
  size_t i;

  for (i = 0; manager->handlers[i]; i++)
    if (strcmp (manager->handlers[i]->name, name) == 0)
      return manager->handlers[i];
  return NULL;
}

void
handler_manager_print_feature_tags (struct custom_handler_manager_s *manager, FILE *out)
{
  size_t i;

  for (i = 0; manager->handlers[i]; i++)
    fprintf (out, "+%s ", manager->handlers[i]->feature_string);
}

static int
find_handler_for_container (struct custom_handler_manager_s *manager,
                            libcrun_container_t *container,
                            struct custom_handler_s **out,
                            void **cookie,
                            libcrun_error_t *err)
{
  size_t i;

  *out = NULL;
  *cookie = NULL;

  for (i = 0; manager->handlers[i]; i++)
    {
      int ret;

      if (manager->handlers[i]->can_handle_container == NULL)
        continue;

      ret = manager->handlers[i]->can_handle_container (container, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (ret)
        {
          *out = manager->handlers[i];
          return (*out)->load (cookie, err);
        }
    }

  return 0;
}

int
libcrun_configure_handler (struct custom_handler_manager_s *manager,
                           libcrun_context_t *context,
                           libcrun_container_t *container,
                           struct custom_handler_s **out,
                           void **cookie,
                           libcrun_error_t *err)
{
  const char *explicit_handler;
  const char *annotation;

  *out = NULL;
  *cookie = NULL;

  annotation = find_annotation (container, "run.oci.handler");

  /* Fail with EACCESS if global handler is already configured and there was a attempt to override it via spec.  */
  if (context->handler != NULL && annotation != NULL)
    return crun_make_error (err, EACCES, "invalid attempt to override already configured global handler: `%s`", context->handler);

  explicit_handler = context->handler ? context->handler : annotation;

  /* If an explicit handler was requested, use it.  */
  if (explicit_handler)
    {
      if (manager == NULL)
        return crun_make_error (err, 0, "handler requested but no manager configured: `%s`", context->handler);

      *out = handler_by_name (manager, explicit_handler);
      if (*out == NULL)
        return crun_make_error (err, 0, "invalid handler specified `%s`", explicit_handler);

      return (*out)->load (cookie, err);
    }

  if (manager == NULL)
    return 0;

  return find_handler_for_container (manager, container, out, cookie, err);
}
