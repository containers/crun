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
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_LIBKRUN
#  include <libkrun.h>
#endif

/* libkrun has a hard-limit of 8 vCPUs per microVM. */
#define LIBKRUN_MAX_VCPUS 8

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
    error (EXIT_FAILURE, 0, "could not find symbol in `libkrun.so`");

  /* If sched_getaffinity fails, default to 1 vcpu.  */
  num_vcpus = 1;
  /* If no memory limit is specified, default to 2G.  */
  ram_mib = 2 * 1024;

  if (def && def->linux && def->linux->resources && def->linux->resources->memory
      && def->linux->resources->memory->limit_present)
    ram_mib = def->linux->resources->memory->limit / (1024 * 1024);

  CPU_ZERO (&set);
  if (sched_getaffinity (getpid (), sizeof (set), &set) == 0)
    num_vcpus = MIN (CPU_COUNT (&set), LIBKRUN_MAX_VCPUS);

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

  handle = dlopen ("libkrun.so.1", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libkrun.so.1`: %s", dlerror ());

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

struct custom_handler_s handler_libkrun = {
  .name = "krun",
  .feature_string = "LIBKRUN",
  .load = libkrun_load,
  .unload = libkrun_unload,
  .exec_func = libkrun_exec,
  .configure_container = libkrun_configure_container,
};

#endif
