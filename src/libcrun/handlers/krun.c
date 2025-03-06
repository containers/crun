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
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <sched.h>
#include <ocispec/runtime_spec_schema_config_schema.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_LIBKRUN
#  include <libkrun.h>
#endif

/* libkrun has a hard-limit of 8 vCPUs per microVM. */
#define LIBKRUN_MAX_VCPUS 8

#define KRUN_CONFIG_FILE ".krun_config.json"

struct krun_config
{
  void *handle;
  void *handle_sev;
  bool sev;
};

/* libkrun handler.  */
#if HAVE_DLOPEN && HAVE_LIBKRUN
static int
libkrun_exec (void *cookie, libcrun_container_t *container, const char *pathname, char *const argv[])
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int32_t (*krun_set_log_level) (uint32_t level);
  int32_t (*krun_create_ctx) ();
  int (*krun_start_enter) (uint32_t ctx_id);
  int32_t (*krun_set_vm_config) (uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);
  int32_t (*krun_set_root) (uint32_t ctx_id, const char *root_path);
  int32_t (*krun_set_root_disk) (uint32_t ctx_id, const char *disk_path);
  int32_t (*krun_set_workdir) (uint32_t ctx_id, const char *workdir_path);
  int32_t (*krun_set_exec) (uint32_t ctx_id, const char *exec_path, char *const argv[], char *const envp[]);
  int32_t (*krun_set_tee_config_file) (uint32_t ctx_id, const char *file_path);
  struct krun_config *kconf = (struct krun_config *) cookie;
  void *handle;
  uint32_t num_vcpus, ram_mib;
  int32_t ctx_id, ret;
  cpu_set_t set;
  char *const envp[] = { 0 };

  if (access ("/krun-sev.json", F_OK) == 0)
    {
      if (kconf->handle_sev == NULL)
        error (EXIT_FAILURE, 0, "the container requires libkrun-sev but it's not available");
      handle = kconf->handle_sev;
      kconf->sev = true;
    }
  else
    {
      if (kconf->handle == NULL)
        error (EXIT_FAILURE, 0, "the container requires libkrun but it's not available");
      handle = kconf->handle;
      kconf->sev = false;
    }

  krun_set_log_level = dlsym (handle, "krun_set_log_level");
  krun_create_ctx = dlsym (handle, "krun_create_ctx");
  krun_start_enter = dlsym (handle, "krun_start_enter");
  if (krun_set_log_level == NULL || krun_create_ctx == NULL
      || krun_start_enter == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in `libkrun.so`");

  /* Set log level to "error" */
  krun_set_log_level (1);

  ctx_id = krun_create_ctx ();
  if (UNLIKELY (ctx_id < 0))
    error (EXIT_FAILURE, -ctx_id, "could not create krun context");

  if (kconf->sev)
    {
      krun_set_root_disk = dlsym (handle, "krun_set_root_disk");
      krun_set_tee_config_file = dlsym (handle, "krun_set_tee_config_file");
      if (krun_set_root_disk == NULL || krun_set_tee_config_file == NULL)
        error (EXIT_FAILURE, 0, "could not find symbol in `libkrun-sev.so`");

      ret = krun_set_root_disk (ctx_id, "/disk.img");
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set root disk");

      ret = krun_set_tee_config_file (ctx_id, "/krun-sev.json");
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set krun tee config file");
    }
  else
    {
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

      krun_set_vm_config = dlsym (handle, "krun_set_vm_config");
      krun_set_root = dlsym (handle, "krun_set_root");
      krun_set_workdir = dlsym (handle, "krun_set_workdir");
      krun_set_exec = dlsym (handle, "krun_set_exec");
      if (krun_set_vm_config == NULL || krun_set_root == NULL
          || krun_set_exec == NULL)
        error (EXIT_FAILURE, 0, "could not find symbol in `libkrun.so`");

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

      ret = krun_set_exec (ctx_id, pathname, &argv[1], &envp[0]);
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set krun executable");
    }
  ret = krun_start_enter (ctx_id);
  return -ret;
}

/* libkrun_create_kvm_device: explicitly adds kvm device.  */
static int
libkrun_configure_container (void *cookie, enum handler_configure_phase phase,
                             libcrun_context_t *context, libcrun_container_t *container,
                             const char *rootfs, libcrun_error_t *err)
{
  int ret, rootfsfd;
  size_t i;
  struct krun_config *kconf = (struct krun_config *) cookie;
  struct device_s kvm_device = { "/dev/kvm", "c", 10, 232, 0666, 0, 0 };
  struct device_s sev_device = { "/dev/sev", "c", 10, 124, 0666, 0, 0 };
  cleanup_close int devfd = -1;
  cleanup_close int rootfsfd_cleanup = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  bool create_sev = false;
  bool is_user_ns;

  if (rootfs == NULL)
    rootfsfd = AT_FDCWD;
  else
    {
      rootfsfd = rootfsfd_cleanup = open (rootfs, O_PATH | O_CLOEXEC);
      if (UNLIKELY (rootfsfd < 0))
        return crun_make_error (err, errno, "open `%s`", rootfs);
    }

  if (phase == HANDLER_CONFIGURE_BEFORE_MOUNTS)
    {
      cleanup_free char *origin_config_path = NULL;
      cleanup_free char *state_dir = NULL;
      cleanup_free char *config = NULL;
      cleanup_close int fd = -1;
      size_t config_size;

      ret = libcrun_get_state_directory (&state_dir, context->state_root, context->id, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&origin_config_path, err, state_dir, "config.json", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = read_all_file (origin_config_path, &config, &config_size, err);
      if (UNLIKELY (ret < 0))
        return ret;

      /* CVE-2025-24965: the content below rootfs cannot be trusted because it is controlled by the user.  We
         must ensure the file is opened below the rootfs directory.  */
      fd = safe_openat (rootfsfd, rootfs, KRUN_CONFIG_FILE, WRITE_FILE_DEFAULT_FLAGS | O_NOFOLLOW, S_IRUSR | S_IRGRP | S_IROTH, err);
      if (UNLIKELY (fd < 0))
        return fd;

      ret = safe_write (fd, KRUN_CONFIG_FILE, config, config_size, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (phase != HANDLER_CONFIGURE_AFTER_MOUNTS)
    return 0;

  /* Do nothing if /dev/kvm is already present in spec */
  for (i = 0; i < def->linux->devices_len; i++)
    {
      if (strcmp (def->linux->devices[i]->path, "/dev/kvm") == 0)
        return 0;
    }

  if (kconf->handle_sev != NULL)
    {
      create_sev = true;
      for (i = 0; i < def->linux->devices_len; i++)
        {
          if (strcmp (def->linux->devices[i]->path, "/dev/sev") == 0)
            create_sev = false;
        }
    }

  devfd = openat (rootfsfd, "dev", O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (devfd < 0))
    return crun_make_error (err, errno, "open /dev directory in `%s`", rootfs);

  ret = check_running_in_user_namespace (err);
  if (UNLIKELY (ret < 0))
    return ret;
  is_user_ns = ret;

  ret = libcrun_create_dev (container, devfd, -1, &kvm_device, is_user_ns, true, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (create_sev)
    {
      ret = libcrun_create_dev (container, devfd, -1, &sev_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
libkrun_load (void **cookie, libcrun_error_t *err)
{
  struct krun_config *kconf;
  const char *libkrun_so = "libkrun.so.1";
  const char *libkrun_sev_so = "libkrun-sev.so.1";

  kconf = malloc (sizeof (struct krun_config));
  if (kconf == NULL)
    return crun_make_error (err, 0, "could not allocate memory for krun_config");

  kconf->handle = dlopen (libkrun_so, RTLD_NOW);
  kconf->handle_sev = dlopen (libkrun_sev_so, RTLD_NOW);

  if (kconf->handle == NULL && kconf->handle_sev == NULL)
    {
      free (kconf);
      return crun_make_error (err, 0, "failed to open `%s` and `%s` for krun_config", libkrun_so, libkrun_sev_so);
    }

  kconf->sev = false;

  *cookie = kconf;

  return 0;
}

static int
libkrun_unload (void *cookie, libcrun_error_t *err)
{
  int r;

  struct krun_config *kconf = (struct krun_config *) cookie;
  if (kconf != NULL)
    {
      if (kconf->handle != NULL)
        {
          r = dlclose (kconf->handle);
          if (UNLIKELY (r != 0))
            return crun_make_error (err, 0, "could not unload handle: `%s`", dlerror ());
        }
      if (kconf->handle_sev != NULL)
        {
          r = dlclose (kconf->handle_sev);
          if (UNLIKELY (r != 0))
            return crun_make_error (err, 0, "could not unload handle_sev: `%s`", dlerror ());
        }
    }
  return 0;
}

static runtime_spec_schema_defs_linux_device_cgroup *
make_oci_spec_dev (const char *type, dev_t device, bool allow, const char *access)
{
  runtime_spec_schema_defs_linux_device_cgroup *dev = xmalloc0 (sizeof (*dev));

  dev->allow = allow;
  dev->allow_present = 1;

  dev->type = xstrdup (type);

  dev->major = major (device);
  dev->major_present = 1;

  dev->minor = minor (device);
  dev->minor_present = 1;

  dev->access = xstrdup (access);

  return dev;
}

static int
libkrun_modify_oci_configuration (void *cookie arg_unused, libcrun_context_t *context arg_unused,
                                  runtime_spec_schema_config_schema *def,
                                  libcrun_error_t *err)
{
  const size_t device_size = sizeof (runtime_spec_schema_defs_linux_device_cgroup);
  struct stat st_kvm, st_sev;
  bool has_sev = true;
  size_t len;
  int ret;

  if (def->linux == NULL || def->linux->resources == NULL
      || def->linux->resources->devices == NULL)
    return 0;

  /* Always allow the /dev/kvm device.  */

  ret = stat ("/dev/kvm", &st_kvm);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "stat `/dev/kvm`");

  ret = stat ("/dev/sev", &st_sev);
  if (UNLIKELY (ret < 0))
    {
      if (errno != ENOENT)
        return crun_make_error (err, errno, "stat `/dev/sev`");
      has_sev = false;
    }

  len = def->linux->resources->devices_len;
  def->linux->resources->devices = xrealloc (def->linux->resources->devices,
                                             device_size * (len + 2 + (has_sev ? 1 : 0)));

  def->linux->resources->devices[len] = make_oci_spec_dev ("a", st_kvm.st_rdev, true, "rwm");
  if (has_sev)
    def->linux->resources->devices[len + 1] = make_oci_spec_dev ("a", st_sev.st_rdev, true, "rwm");

  def->linux->resources->devices_len += has_sev ? 2 : 1;

  return 0;
}

struct custom_handler_s handler_libkrun = {
  .name = "krun",
  .alias = NULL,
  .feature_string = "LIBKRUN",
  .load = libkrun_load,
  .unload = libkrun_unload,
  .run_func = libkrun_exec,
  .configure_container = libkrun_configure_container,
  .modify_oci_configuration = libkrun_modify_oci_configuration,
};

#endif
