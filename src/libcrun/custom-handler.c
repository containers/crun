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

#if HAVE_WASMER
#  define WASMER_BUF_SIZE 128
static int
wasmer_do_exec (void *container, void *arg, const char *pathname, char *const argv[])
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

  wat2wasm = dlsym (handle, "wat2wasm");
  wasm_module_delete = dlsym (handle, "wasm_module_delete");
  wasm_instance_delete = dlsym (handle, "wasm_instance_delete");
  wasm_engine_delete = dlsym (handle, "wasm_engine_delete");
  wasm_store_delete = dlsym (handle, "wasm_store_delete");
  wasm_func_call = dlsym (handle, "wasm_func_call");
  wasm_extern_as_func = dlsym (handle, "wasm_extern_as_func");
  wasm_instance_exports = dlsym (handle, "wasm_instance_exports");
  wasm_instance_new = dlsym (handle, "wasm_instance_new");
  wasm_store_new = dlsym (handle, "wasm_store_new");
  wasm_module_new = dlsym (handle, "wasm_module_new");
  wasm_engine_new = dlsym (handle, "wasm_engine_new");
  wasm_byte_vec_new = dlsym (handle, "wasm_byte_vec_new");
  wasm_byte_vec_delete = dlsym (handle, "wasm_byte_vec_delete");
  wasm_extern_vec_delete = dlsym (handle, "wasm_extern_vec_delete");
  wasm_importtype_vec_delete = dlsym (handle, "wasm_importtype_vec_delete");
  wasm_byte_vec_new_uninitialized = dlsym (handle, "wasm_byte_vec_new_uninitialized");
  wasi_config_new = dlsym (handle, "wasi_config_new");
  wasi_config_arg = dlsym (handle, "wasi_config_arg");
  wasi_config_capture_stdout = dlsym (handle, "wasi_config_capture_stdout");
  wasi_env_new = dlsym (handle, "wasi_env_new");
  wasm_module_imports = dlsym (handle, "wasm_module_imports");
  wasm_extern_vec_new_uninitialized = dlsym (handle, "wasm_extern_vec_new_uninitialized");
  wasi_get_imports = dlsym (handle, "wasi_get_imports");
  wasi_get_start_function = dlsym (handle, "wasi_get_start_function");
  wasi_env_read_stdout = dlsym (handle, "wasi_env_read_stdout");
  wasi_env_delete = dlsym (handle, "wasi_env_delete");
  wasm_func_delete = dlsym (handle, "wasm_func_delete");

  if (wat2wasm == NULL || wasm_module_delete == NULL || wasm_instance_delete == NULL || wasm_engine_delete == NULL || wasm_store_delete == NULL
      || wasm_func_call == NULL || wasm_extern_as_func == NULL || wasm_instance_exports == NULL || wasm_instance_new == NULL
      || wasm_store_new == NULL || wasm_engine_new == NULL || wasm_byte_vec_new == NULL || wasm_byte_vec_delete == NULL || wasm_extern_vec_delete == NULL || wasm_byte_vec_new_uninitialized == NULL || wasi_config_new == NULL || wasi_config_capture_stdout == NULL || wasi_env_new == NULL || wasm_module_imports == NULL || wasi_env_read_stdout == NULL || wasi_env_delete == NULL || wasm_func_delete == NULL || wasm_importtype_vec_delete == NULL || wasm_extern_vec_new_uninitialized == NULL || wasi_get_imports == NULL || wasi_get_start_function == NULL)
    {
      fprintf (stderr, "could not find symbol in `libwasmer.so`");
      dlclose (handle);
      return -1;
    }

  wat_wasm_file = fopen (pathname, "rb");

  if (! wat_wasm_file)
    error (EXIT_FAILURE, errno, "error opening wat/wasm module");

  fseek (wat_wasm_file, 0L, SEEK_END);
  file_size = ftell (wat_wasm_file);
  fseek (wat_wasm_file, 0L, SEEK_SET);

  wasm_byte_vec_new_uninitialized (&binary_bytes, file_size);

  if (fread (binary_bytes.data, file_size, 1, wat_wasm_file) != 1)
    error (EXIT_FAILURE, errno, "error loading wat/wasm module");

  // we can close entrypoint file
  fclose (wat_wasm_file);

  // we have received a wat file
  // convert wat to wasm
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

  // process wasi args
  // count number of external arguments given
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
  // Instantiate.
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

  // Extract export.
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
            // relay wasi output to stdout
            ret = safe_write (STDOUT_FILENO, buffer, (ssize_t) data_read_size);
            if (UNLIKELY (ret < 0))
              error (EXIT_FAILURE, errno, "error while writing wasi output to stdout");
          }
    } while (WASMER_BUF_SIZE == data_read_size);
  }

  wasm_extern_vec_delete (&exports);
  wasm_extern_vec_delete (&imports);

  // Shut down.
  wasm_func_delete (run_func);
  wasi_env_delete (wasi_env);
  wasm_store_delete (store);
  wasm_engine_delete (engine);
  return 0;
}
#endif

#if HAVE_DLOPEN && HAVE_WASMEDGE
static int
wasmedge_do_exec (void *container, void *handle, const char *pathname, char *const argv[])
{
  runtime_spec_schema_config_schema *def = ((libcrun_container_t *) container)->container_def;
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

  WasmEdge_ConfigureCreate = dlsym (handle, "WasmEdge_ConfigureCreate");
  WasmEdge_ConfigureDelete = dlsym (handle, "WasmEdge_ConfigureDelete");
  WasmEdge_ConfigureAddProposal = dlsym (handle, "WasmEdge_ConfigureAddProposal");
  WasmEdge_ConfigureAddHostRegistration = dlsym (handle, "WasmEdge_ConfigureAddHostRegistration");
  WasmEdge_VMCreate = dlsym (handle, "WasmEdge_VMCreate");
  WasmEdge_VMDelete = dlsym (handle, "WasmEdge_VMDelete");
  WasmEdge_VMRegisterModuleFromFile = dlsym (handle, "WasmEdge_VMRegisterModuleFromFile");
  WasmEdge_VMGetImportModuleContext = dlsym (handle, "WasmEdge_VMGetImportModuleContext");
  WasmEdge_ImportObjectInitWASI = dlsym (handle, "WasmEdge_ImportObjectInitWASI");
  WasmEdge_ImportObjectInitWasmEdgeProcess = dlsym (handle, "WasmEdge_ImportObjectInitWasmEdgeProcess");
  WasmEdge_VMRunWasmFromFile = dlsym (handle, "WasmEdge_VMRunWasmFromFile");
  WasmEdge_ResultOK = dlsym (handle, "WasmEdge_ResultOK");
  WasmEdge_StringCreateByCString = dlsym (handle, "WasmEdge_StringCreateByCString");
  if (WasmEdge_ConfigureCreate == NULL || WasmEdge_ConfigureDelete == NULL || WasmEdge_ConfigureAddProposal == NULL || WasmEdge_ConfigureAddHostRegistration == NULL || WasmEdge_VMCreate == NULL || WasmEdge_VMDelete == NULL || WasmEdge_VMRegisterModuleFromFile == NULL || WasmEdge_VMGetImportModuleContext == NULL || WasmEdge_ImportObjectInitWASI == NULL || WasmEdge_ImportObjectInitWasmEdgeProcess == NULL || WasmEdge_VMRunWasmFromFile == NULL || WasmEdge_ResultOK == NULL || WasmEdge_StringCreateByCString == NULL)
    {
      fprintf (stderr, "could not find symbol in `libwasmedge.so`");
      dlclose (handle);
      return -1;
    }

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
  return 0;
}
#endif

#if HAVE_DLOPEN && HAVE_LIBKRUN
static int
libkrun_do_exec (void *container, void *arg, const char *pathname, char *const argv[])
{
  runtime_spec_schema_config_schema *def = ((libcrun_container_t *) container)->container_def;
  int32_t (*krun_create_ctx) ();
  int (*krun_start_enter) (uint32_t ctx_id);
  int32_t (*krun_set_vm_config) (uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);
  int32_t (*krun_set_root) (uint32_t ctx_id, const char *root_path);
  int32_t (*krun_set_workdir) (uint32_t ctx_id, const char *workdir_path);
  int32_t (*krun_set_exec) (uint32_t ctx_id, const char *exec_path, char *const argv[], char *const envp[]);
  void *handle = arg;
  uint32_t num_vcpus, ram_mib;
  int32_t ctx_id, ret;
  cpu_set_t set;

  krun_create_ctx = dlsym (handle, "krun_create_ctx");
  krun_start_enter = dlsym (handle, "krun_start_enter");
  krun_set_vm_config = dlsym (handle, "krun_set_vm_config");
  krun_set_root = dlsym (handle, "krun_set_root");
  krun_set_workdir = dlsym (handle, "krun_set_workdir");
  krun_set_exec = dlsym (handle, "krun_set_exec");
  if (krun_create_ctx == NULL || krun_start_enter == NULL || krun_set_vm_config == NULL || krun_set_root == NULL
      || krun_set_exec == NULL)
    {
      fprintf (stderr, "could not find symbol in `libkrun.so`");
      dlclose (handle);
      return -1;
    }

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
#endif

#if HAVE_DLOPEN && HAVE_LIBKRUN
/* libcrun_create_kvm_device: explicitly adds kvm device.  */
static int
libcrun_create_kvm_device (libcrun_context_t *context, libcrun_container_t *container, const char *rootfs, libcrun_error_t *err)
{
  int ret, rootfsfd;
  size_t i;
  struct device_s kvm_device = { "/dev/kvm", "c", 10, 232, 0666, 0, 0 };
  cleanup_close int devfd = -1;
  cleanup_close int rootfsfd_cleanup = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  const char *rootfs = get_private_data (container)->rootfs;
  bool is_user_ns;

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
#endif

static int
libcrun_configure_libkrun (struct custom_handler_s *out, libcrun_error_t *err)
{
#if HAVE_DLOPEN && HAVE_LIBKRUN
  void *handle;
#endif

#if HAVE_DLOPEN && HAVE_LIBKRUN
  handle = dlopen ("libkrun.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libkrun.so`: %s", dlerror ());

  out->exec_func = libkrun_do_exec;
  out->exec_func_arg = handle;
  out->post_configure_mounts = libcrun_create_kvm_device;

  return 0;
#else
  (void) out;
  return crun_make_error (err, ENOTSUP, "libkrun or dlopen not present");
#endif
}

static int
libcrun_configure_wasmer (struct custom_handler_s *out, libcrun_error_t *err)
{
#if HAVE_DLOPEN && HAVE_WASMER
  void *handle;

  handle = dlopen ("libwasmer.so", RTLD_NOW);
  if (handle != NULL)
    {
      out->exec_func = wasmer_do_exec;
      out->exec_func_arg = handle;
      return 0;
    }
#endif

  (void) out;
  return crun_make_error (err, ENOTSUP, "wasmer support not present");
}

static int
libcrun_configure_wasmedge (struct custom_handler_s *out, libcrun_error_t *err)
{
#if HAVE_DLOPEN && HAVE_WASMEDGE
  void *handle;

  handle = dlopen ("libwasmedge_c.so", RTLD_NOW);
  if (handle != NULL)
    {
      out->exec_func = wasmedge_do_exec;
      out->exec_func_arg = handle;
      return 0;
    }
#endif

  (void) out;
  return crun_make_error (err, ENOTSUP, "wasmedge support not present");
}

int
libcrun_configure_handler (libcrun_context_t *context, libcrun_container_t *container, struct custom_handler_s *out, libcrun_error_t *err)
{
  const char *annotation;

  annotation = find_annotation (container, "run.oci.handler");

  /* Fail with EACCESS if global handler is already configured and there was a attempt to override it via spec. */
  if (context->handler != NULL && annotation != NULL)
    return crun_make_error (err, EACCES, "invalid attempt to override already configured global handler: `%s`", context->handler);

  /* If rootfs is a wasm variant and runtime has wasmer support */
#if HAVE_DLOPEN && (HAVE_WASMER || HAVE_WASMEDGE)
  const char *wasm_image;
  wasm_image = find_annotation (container, "module.wasm.image/variant");
#endif

  /* In selection order global_handler takes more priority over handler configured via spec annotations. */
  /* Check if crun is being invoked as krun via global_handler. */
#if HAVE_DLOPEN && HAVE_LIBKRUN
  if (context->handler != NULL && (strcmp (context->handler, "krun") == 0))
      return libcrun_configure_libkrun (out, err);
#endif

    /* If rootfs is a wasm variant and runtime has wasmer support */
    /* Fallback to "wasm" handler but explictly setting handle to "wasm" */
    /* Read more here: https://github.com/solo-io/wasm/blob/master/spec/spec-compat.md#annotation */
#if HAVE_DLOPEN && (HAVE_WASMER || HAVE_WASMEDGE)
  if (wasm_image != NULL && (strcmp (wasm_image, "compat") == 0))
    {
      context->handler = "wasm";
      return libcrun_configure_wasm (out, err);
    }
#endif

  /* Do nothing: no annotations or global_handler configured */
  if (annotation == NULL)
    return 0;

  if (strcmp (annotation, "krun") == 0)
    {
      /* set global_handler equivalent to "krun" so that we can mount kvm device */
      context->handler = annotation;
      return libcrun_configure_libkrun (out, err);
    }

  if (strcmp (annotation, "wasm") == 0)
    {
      /* set global_handler equivalent to "wasm" so that we can invoke wasmer runtime */
      context->handler = annotation;
#if HAVE_DLOPEN && HAVE_WASMER
      return libcrun_configure_wasmer (out, err);
#endif

#if HAVE_DLOPEN && HAVE_WASMEDGE
      return libcrun_configure_wasmedge (out, err);
#endif
    }

  return crun_make_error (err, EINVAL, "invalid handler specified `%s`", annotation);
}

void
print_handlers_feature_tags (FILE *out arg_unused)
{
#ifdef HAVE_WASMER
  fprintf (stream, "+WASM:wasmer ");
#elif defined HAVE_WASMEDGE
  fprintf (stream, "+WASM:wasmedge ");
#endif
#ifdef HAVE_LIBKRUN
  fprintf (stream, "+LIBKRUN ");
#endif
}
