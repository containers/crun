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

/* libkrun has a hard-limit of 16 vCPUs per microVM. */
#define LIBKRUN_MAX_VCPUS 16

/* crun dumps the container configuration into this file, which will be read by
 * libkrun to set up the environment for the workload inside the microVM.
 */
#define KRUN_CONFIG_FILE ".krun_config.json"

/* The presence of this file indicates this is a container intended to be run
 * as a confidential workload inside a SEV-powered TEE.
 */
#define KRUN_SEV_FILE "/krun-sev.json"

/* This file contains configuration parameters for the microVM. crun needs to
 * read and parse it, using the information obtained from it to configure
 * libkrun as required.
 */
#define KRUN_VM_FILE "/.krun_vm.json"

#define KRUN_FLAVOR_NITRO "aws-nitro"
#define KRUN_FLAVOR_SEV "sev"

struct krun_config
{
  void *handle;
  void *handle_sev;
  void *handle_nitro;
  bool sev;
  bool nitro;
  int32_t ctx_id;
  int32_t ctx_id_sev;
  int32_t ctx_id_nitro;
  bool has_kvm;
  bool has_nitro;
};

/* libkrun handler.  */
#if HAVE_DLOPEN && HAVE_LIBKRUN
static int32_t
libkrun_create_context (void *handle, libcrun_error_t *err)
{
  int32_t (*krun_create_ctx) ();
  int32_t ctx_id;

  krun_create_ctx = dlsym (handle, "krun_create_ctx");
  if (krun_create_ctx == NULL)
    return crun_make_error (err, 0, "could not find symbol in the krun library");

  ctx_id = krun_create_ctx ();
  if (UNLIKELY (ctx_id < 0))
    return crun_make_error (err, -ctx_id, "could not create krun context");

  return ctx_id;
}

static int
libkrun_configure_kernel (uint32_t ctx_id, void *handle, yajl_val *config_tree, libcrun_error_t *err)
{
  int32_t (*krun_set_kernel) (uint32_t ctx_id, const char *kernel_path,
                              uint32_t kernel_format, const char *initrd_path, const char *kernel_cmdline);
  const char *path_kernel_path[] = { "kernel_path", (const char *) 0 };
  const char *path_kernel_format[] = { "kernel_format", (const char *) 0 };
  const char *path_initrd_path[] = { "initrd_path", (const char *) 0 };
  const char *path_kernel_cmdline[] = { "kernel_cmdline", (const char *) 0 };
  yajl_val kernel_path = NULL;
  yajl_val kernel_format = NULL;
  yajl_val val_initrd_path = NULL;
  yajl_val val_kernel_cmdline = NULL;
  char *initrd_path = NULL;
  char *kernel_cmdline = NULL;
  int ret;

  /* kernel_path and kernel_format must be present */
  kernel_path = yajl_tree_get (*config_tree, path_kernel_path, yajl_t_string);
  if (kernel_path == NULL || ! YAJL_IS_STRING (kernel_path))
    return 0;

  kernel_format = yajl_tree_get (*config_tree, path_kernel_format, yajl_t_number);
  if (kernel_format == NULL || ! YAJL_IS_INTEGER (kernel_format))
    return 0;

  /* initrd and kernel_cmdline are optional */
  val_initrd_path = yajl_tree_get (*config_tree, path_initrd_path, yajl_t_string);
  if (val_initrd_path != NULL && YAJL_IS_STRING (val_initrd_path))
    initrd_path = YAJL_GET_STRING (val_initrd_path);

  val_kernel_cmdline = yajl_tree_get (*config_tree, path_kernel_cmdline, yajl_t_string);
  if (val_kernel_cmdline != NULL && YAJL_IS_STRING (val_kernel_cmdline))
    kernel_cmdline = YAJL_GET_STRING (val_kernel_cmdline);

  krun_set_kernel = dlsym (handle, "krun_set_kernel");
  if (krun_set_kernel == NULL)
    return crun_make_error (err, 0, "could not find symbol in krun library");

  ret = krun_set_kernel (ctx_id,
                         YAJL_GET_STRING (kernel_path),
                         YAJL_GET_INTEGER (kernel_format),
                         initrd_path, kernel_cmdline);

  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "could not configure a krun external kernel");

  return 0;
}

static int
libkrun_configure_nitro (uint32_t ctx_id, void *handle, yajl_val *config_tree, libcrun_error_t *err)
{
  int32_t (*krun_nitro_set_image) (uint32_t ctx_id, const char *image_path, uint32_t image_type);
  int32_t (*krun_nitro_set_start_flags) (uint32_t ctx_id, uint64_t start_flags);
  const char *path_eif[] = { "eif_file", (const char *) 0 };
  yajl_val val_eif_image = NULL;
  uint64_t start_flags = 1;
  char *eif_image = NULL;
  int ret;

  val_eif_image = yajl_tree_get (*config_tree, path_eif, yajl_t_string);
  if (val_eif_image == NULL || ! YAJL_IS_STRING (val_eif_image))
    return crun_make_error (err, 0, "invalid Enclave Image Format file parameter");

  eif_image = YAJL_GET_STRING (val_eif_image);

  krun_nitro_set_image = dlsym (handle, "krun_nitro_set_image");
  if (krun_nitro_set_image == NULL)
    return crun_make_error (err, 0, "could not find symbol in krun library");

  krun_nitro_set_start_flags = dlsym (handle, "krun_nitro_set_start_flags");
  if (krun_nitro_set_start_flags == NULL)
    return crun_make_error (err, 0, "could not find symbol in krun library");

  ret = krun_nitro_set_image (ctx_id, eif_image, KRUN_NITRO_IMG_TYPE_EIF);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "could not configure a krun nitro EIF image");

  ret = krun_nitro_set_start_flags (ctx_id, 1);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "could not configure a krun nitro start flags");

  return 0;
}

static int
libkrun_enable_virtio_gpu (struct krun_config *kconf)
{
  int32_t (*krun_set_gpu_options) (uint32_t ctx_id, uint32_t virgl_flags);
  krun_set_gpu_options = dlsym (kconf->handle, "krun_set_gpu_options");

  // ignore if dlsym fails
  if (krun_set_gpu_options == NULL)
    return 0;

  uint32_t virgl_flags = VIRGLRENDERER_NO_VIRGL |          /* do not expose OpenGL */
                         VIRGLRENDERER_RENDER_SERVER |     /* start a render server and move GPU rendering to the render server */
                         VIRGLRENDERER_VENUS |             /* enable venus renderer */
                         VIRGLRENDERER_THREAD_SYNC |       /* wait for sync objects in thread rather than polling */
                         VIRGLRENDERER_USE_ASYNC_FENCE_CB; /* used in conjunction with VIRGLRENDERER_THREAD_SYNC */
  return krun_set_gpu_options (kconf->ctx_id, virgl_flags);
}

static int
libkrun_read_vm_config (yajl_val *config_tree, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *config = NULL;
  struct parser_context ctx = { 0, stderr };

  if (access (KRUN_VM_FILE, F_OK) != 0)
    return 0;

  ret = read_all_file (KRUN_VM_FILE, &config, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = parse_json_file (config_tree, config, &ctx, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
libkrun_configure_vm (uint32_t ctx_id, void *handle, bool *configured, yajl_val *config_tree, libcrun_error_t *err)
{
  int32_t (*krun_set_vm_config) (uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);
  yajl_val cpus = NULL;
  yajl_val ram_mib = NULL;
  const char *path_cpus[] = { "cpus", (const char *) 0 };
  const char *path_ram_mib[] = { "ram_mib", (const char *) 0 };
  int ret;

  if (*config_tree == NULL)
    return 0;

  /* Try to configure an external kernel. If the configuration file doesn't
   * specify a kernel, libkrun automatically fall back to using libkrunfw,
   * if the library is present and was loaded while creating the context.
   */
  ret = libkrun_configure_kernel (ctx_id, handle, config_tree, err);
  if (UNLIKELY (ret))
    return ret;

  cpus = yajl_tree_get (*config_tree, path_cpus, yajl_t_number);
  ram_mib = yajl_tree_get (*config_tree, path_ram_mib, yajl_t_number);
  /* Both cpus and ram_mib must be present at the same time */
  if (cpus == NULL || ram_mib == NULL || ! YAJL_IS_INTEGER (cpus) || ! YAJL_IS_INTEGER (ram_mib))
    return 0;

  krun_set_vm_config = dlsym (handle, "krun_set_vm_config");

  if (krun_set_vm_config == NULL)
    return crun_make_error (err, 0, "could not find symbol in the krun library");

  ret = krun_set_vm_config (ctx_id, YAJL_GET_INTEGER (cpus), YAJL_GET_INTEGER (ram_mib));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "could not set krun vm configuration");

  *configured = true;

  return 0;
}

static int
libkrun_configure_flavor (void *cookie, yajl_val *config_tree, libcrun_error_t *err)
{
  int ret, sev_indicated = 0, nitro_indicated = 0;
  const char *path_flavor[] = { "flavor", (const char *) 0 };
  struct krun_config *kconf = (struct krun_config *) cookie;
  yajl_val val_flavor = NULL;
  char *flavor = NULL;
  void *close_handles[2];

  close_handles[0] = NULL;
  close_handles[1] = NULL;

  // Read if the SEV flavor was indicated in the krun VM config.
  val_flavor = yajl_tree_get (*config_tree, path_flavor, yajl_t_string);
  if (val_flavor != NULL && YAJL_IS_STRING (val_flavor))
    {
      flavor = YAJL_GET_STRING (val_flavor);

      // The SEV flavor will be used if the krun VM config indicates to use SEV
      // within the "flavor" field.
      sev_indicated |= strcmp (flavor, KRUN_FLAVOR_SEV) == 0;
      nitro_indicated |= strcmp (flavor, KRUN_FLAVOR_NITRO) == 0;
    }

  // To maintain backward compatibility, also use the SEV flavor if the
  // KRUN_SEV_FILE was found.
  sev_indicated |= access (KRUN_SEV_FILE, F_OK) == 0;

  if (sev_indicated)
    {
      if (kconf->handle_sev == NULL)
        error (EXIT_FAILURE, 0, "the container requires libkrun-sev but it's not available");

      close_handles[0] = kconf->handle;
      close_handles[1] = kconf->handle_nitro;

      kconf->handle = kconf->handle_sev;
      kconf->ctx_id = kconf->ctx_id_sev;
      kconf->sev = true;
    }
  else if (nitro_indicated)
    {
      if (kconf->handle_nitro == NULL)
        error (EXIT_FAILURE, 0, "the container requires libkrun-nitro but it's not available");

      close_handles[0] = kconf->handle;
      close_handles[1] = kconf->handle_sev;

      kconf->handle = kconf->handle_nitro;
      kconf->ctx_id = kconf->ctx_id_nitro;
      kconf->nitro = true;
    }
  else
    {
      if (kconf->handle == NULL)
        error (EXIT_FAILURE, 0, "the container requires libkrun but it's not available");

      close_handles[0] = kconf->handle_sev;
      close_handles[1] = kconf->handle_nitro;
    }

  // We no longer need the other two libkrun handles.
  for (int i = 0; i < 2; i++)
    {
      if (close_handles[i] == NULL)
        continue;

      ret = dlclose (close_handles[i]);
      if (UNLIKELY (ret != 0))
        return crun_make_error (err, 0, "could not unload handle: `%s`", dlerror ());
    }

  return 0;
}

static int
libkrun_exec (void *cookie, libcrun_container_t *container, const char *pathname, char *const argv[])
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int32_t (*krun_set_log_level) (uint32_t level);
  int (*krun_start_enter) (uint32_t ctx_id);
  int32_t (*krun_set_vm_config) (uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);
  int32_t (*krun_set_root) (uint32_t ctx_id, const char *root_path);
  int32_t (*krun_set_root_disk) (uint32_t ctx_id, const char *disk_path);
  int32_t (*krun_set_tee_config_file) (uint32_t ctx_id, const char *file_path);
  int32_t (*krun_nitro_set_image) (uint32_t ctx_id, const char *image_path, uint32_t image_type);
  struct krun_config *kconf = (struct krun_config *) cookie;
  void *handle;
  uint32_t num_vcpus, ram_mib;
  int32_t ctx_id, ret;
  cpu_set_t set;
  libcrun_error_t err;
  bool configured = false;
  yajl_val config_tree = NULL;

  ret = libkrun_read_vm_config (&config_tree, &err);
  if (UNLIKELY (ret < 0))
    error (EXIT_FAILURE, -ret, "libkrun VM config exists, but unable to parse");

  ret = libkrun_configure_flavor (cookie, &config_tree, &err);
  if (UNLIKELY (ret < 0))
    error (EXIT_FAILURE, -ret, "unable to configure libkrun flavor");

  // /dev/kvm is required for all non-nitro workloads.
  if (! kconf->nitro && ! kconf->has_kvm)
    error (EXIT_FAILURE, -ret, "`/dev/kvm` unavailable");

  handle = kconf->handle;
  ctx_id = kconf->ctx_id;

  krun_set_log_level = dlsym (handle, "krun_set_log_level");
  krun_start_enter = dlsym (handle, "krun_start_enter");
  if (krun_set_log_level == NULL || krun_start_enter == NULL)
    error (EXIT_FAILURE, 0, "could not find symbol in the krun library");

  /* Set log level to "error" */
  krun_set_log_level (1);

  if (kconf->sev)
    {
      krun_set_root_disk = dlsym (handle, "krun_set_root_disk");
      krun_set_tee_config_file = dlsym (handle, "krun_set_tee_config_file");
      if (krun_set_root_disk == NULL || krun_set_tee_config_file == NULL)
        error (EXIT_FAILURE, 0, "could not find symbol in `libkrun-sev.so`");

      ret = krun_set_root_disk (ctx_id, "/disk.img");
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set root disk");

      ret = krun_set_tee_config_file (ctx_id, KRUN_SEV_FILE);
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set krun tee config file");
    }
  else if (kconf->nitro)
    {
      ret = libkrun_configure_nitro (ctx_id, handle, &config_tree, &err);
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not configure krun nitro enclave");
    }
  else
    {
      krun_set_root = dlsym (handle, "krun_set_root");

      if (krun_set_root == NULL)
        error (EXIT_FAILURE, 0, "could not find symbol in `libkrun.so`");

      ret = krun_set_root (ctx_id, "/");
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set krun root");
    }

  ret = libkrun_configure_vm (ctx_id, handle, &configured, &config_tree, &err);
  if (UNLIKELY (ret))
    {
      libcrun_error_t *tmp_err = &err;
      libcrun_error_write_warning_and_release (NULL, &tmp_err);
      error (EXIT_FAILURE, ret, "could not configure krun vm");
    }

  /* If we couldn't configure the microVM using KRUN_VM_FILE, fall back to the
   * legacy configuration logic.
   */
  if (! configured)
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

      if (krun_set_vm_config == NULL)
        error (EXIT_FAILURE, 0, "could not find symbol in `libkrun.so`");

      ret = krun_set_vm_config (ctx_id, num_vcpus, ram_mib);
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set krun vm configuration");

      if (access ("/dev/dri", F_OK) == 0 && access ("/usr/libexec/virgl_render_server", F_OK) == 0)
        {
          ret = libkrun_enable_virtio_gpu (kconf);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  yajl_tree_free (config_tree);

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
  struct device_s nitro_device = { "/dev/nitro_enclaves", "c", 10, 122, 0666, 0, 0 };
  cleanup_close int devfd = -1;
  cleanup_close int rootfsfd_cleanup = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  bool create_sev = false, create_nitro = false;
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
            {
              create_sev = false;
              break;
            }
        }
    }

  if (kconf->handle_nitro != NULL)
    {
      create_nitro = true;
      for (i = 0; i < def->linux->devices_len; i++)
        {
          if (strcmp (def->linux->devices[i]->path, "/dev/nitro_enclaves") == 0)
            {
              create_nitro = false;
              break;
            }
        }
    }

  devfd = openat (rootfsfd, "dev", O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (devfd < 0))
    return crun_make_error (err, errno, "open /dev directory in `%s`", rootfs);

  ret = check_running_in_user_namespace (err);
  if (UNLIKELY (ret < 0))
    return ret;
  is_user_ns = ret;

  if (kconf->has_kvm)
    {
      ret = libcrun_create_dev (container, devfd, -1, &kvm_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (create_sev)
    {
      ret = libcrun_create_dev (container, devfd, -1, &sev_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (create_nitro)
    {
      ret = libcrun_create_dev (container, devfd, -1, &nitro_device, is_user_ns, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
libkrun_load (void **cookie, libcrun_error_t *err)
{
  int32_t ret;
  struct krun_config *kconf;
  const char *libkrun_so = "libkrun.so.1";
  const char *libkrun_sev_so = "libkrun-sev.so.1";
  const char *libkrun_nitro_so = "libkrun-nitro.so.1";

  kconf = malloc (sizeof (struct krun_config));
  if (kconf == NULL)
    return crun_make_error (err, 0, "could not allocate memory for krun_config");

  kconf->handle = dlopen (libkrun_so, RTLD_NOW);
  kconf->handle_sev = dlopen (libkrun_sev_so, RTLD_NOW);
  kconf->handle_nitro = dlopen (libkrun_nitro_so, RTLD_NOW);

  if (kconf->handle == NULL && kconf->handle_sev == NULL && kconf->handle_nitro == NULL)
    {
      free (kconf);
      return crun_make_error (err, 0, "failed to open `%s`, `%s`, and `%s` for krun_config: %s", libkrun_so, libkrun_sev_so, libkrun_nitro_so, dlerror ());
    }

  kconf->sev = false;
  kconf->nitro = false;

  /* Newer versions of libkrun no longer link against libkrunfw and
     instead they open it when creating the context. This implies
     we need to call "krun_create_ctx" before switching namespaces
     or it won't be able to find the library bundling the kernel. */
  if (kconf->handle)
    {
      ret = libkrun_create_context (kconf->handle, err);
      if (UNLIKELY (ret < 0))
        {
          free (kconf);
          return ret;
        }
      kconf->ctx_id = ret;
    }

  if (kconf->handle_sev)
    {
      ret = libkrun_create_context (kconf->handle_sev, err);
      if (UNLIKELY (ret < 0))
        {
          free (kconf);
          return ret;
        }
      kconf->ctx_id_sev = ret;
    }
  if (kconf->handle_nitro)
    {
      ret = libkrun_create_context (kconf->handle_nitro, err);
      if (UNLIKELY (ret < 0))
        {
          free (kconf);
          return ret;
        }
      kconf->ctx_id_nitro = ret;
    }

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
  struct krun_config *kconf = (struct krun_config *) cookie;
  struct stat st_kvm, st_sev, st_nitro;
  bool has_kvm = true, has_sev = true, has_nitro = true;
  size_t len;
  int ret;

  if (def->linux == NULL || def->linux->resources == NULL
      || def->linux->resources->devices == NULL)
    return 0;

  /* Always allow the /dev/kvm device.  */

  ret = stat ("/dev/kvm", &st_kvm);
  if (UNLIKELY (ret < 0))
    {
      if (errno != ENOENT)
        return crun_make_error (err, errno, "stat `/dev/kvm`");
      has_kvm = false;
    }

  ret = stat ("/dev/sev", &st_sev);
  if (UNLIKELY (ret < 0))
    {
      if (errno != ENOENT)
        return crun_make_error (err, errno, "stat `/dev/sev`");
      has_sev = false;
    }

  ret = stat ("/dev/nitro_enclaves", &st_nitro);
  if (UNLIKELY (ret < 0))
    {
      if (errno != ENOENT)
        return crun_make_error (err, errno, "stat `/dev/nitro_enclaves`");
      has_nitro = false;
    }

  if (has_kvm)
    {
      len = def->linux->resources->devices_len;
      def->linux->resources->devices = xrealloc (def->linux->resources->devices,
                                                 device_size * (len + 2 + (has_sev ? 1 : 0)));

      def->linux->resources->devices[len] = make_oci_spec_dev ("a", st_kvm.st_rdev, true, "rwm");
      if (has_sev)
        def->linux->resources->devices[len + 1] = make_oci_spec_dev ("a", st_sev.st_rdev, true, "rwm");

      def->linux->resources->devices_len += has_sev ? 2 : 1;
    }

  if (has_nitro)
    {
      len = def->linux->resources->devices_len;
      def->linux->resources->devices = xrealloc (def->linux->resources->devices,
                                                 device_size * (len + 2));

      def->linux->resources->devices[len] = make_oci_spec_dev ("a", st_nitro.st_rdev, true, "rwm");
      def->linux->resources->devices_len++;
    }

  kconf->has_kvm = has_kvm;
  kconf->has_nitro = has_nitro;

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
