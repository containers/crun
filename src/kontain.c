/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020 Kontain Inc.
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/sysmacros.h>

#include "crun.h"
#include "kontain.h"
#include "debug.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"

static runtime_spec_schema_defs_mount *
build_kontain_bind_mount(char *src, char *dst)
{
  runtime_spec_schema_defs_mount *m = calloc(1, sizeof(runtime_spec_schema_defs_mount));
  if (m != NULL) {
    m->source = strdup(src);
    m->destination = strdup(dst);
#define BIND_MOUNT_OPTIONS_COUNT 2
    m->options = calloc(BIND_MOUNT_OPTIONS_COUNT, sizeof(char *));
    m->options[0] = strdup("rbind");
    m->options[1] = strdup("rprivate");
    m->options_len = BIND_MOUNT_OPTIONS_COUNT;
    m->type = strdup("bind");
  }
  return m;
}

int
add_kontain_bind_mounts(libcrun_container_t *container, const char *privileged)
{
  runtime_spec_schema_config_schema *container_def = container->container_def;
  runtime_spec_schema_defs_mount **mounts = container_def->mounts;
  int mounts_len = container_def->mounts_len;
  int kvmkkm_bind_mount = 0;

  // for unprivileged podman we bind mount /dev/kvm or /dev/kkm
  if (privileged != NULL && strcasecmp(privileged, "false") == 0) {
    kvmkkm_bind_mount = 1;
  }

  int new_mounts_len = mounts_len + 2 + kvmkkm_bind_mount;
  runtime_spec_schema_defs_mount **new_mounts = realloc(mounts, new_mounts_len * sizeof(runtime_spec_schema_defs_mount *));
  if (new_mounts == NULL) {
    return ENOMEM;
  }
  container_def->mounts = new_mounts;
  container_def->mounts[mounts_len] = build_kontain_bind_mount("/opt/kontain/bin/km", "/opt/kontain/bin/km");
  if (container_def->mounts[mounts_len] == NULL)
    return ENOMEM;
  container_def->mounts[mounts_len + 1] = build_kontain_bind_mount("/opt/kontain/runtime/libc.so", "/opt/kontain/runtime/libc.so");
  if (container_def->mounts[mounts_len + 1] == NULL)
    return ENOMEM;
  if (kvmkkm_bind_mount != 0) {
    container_def->mounts[mounts_len + 2] = build_kontain_bind_mount("/dev/kvm", "/dev/kvm");
    if (container_def->mounts[mounts_len + 2] == NULL)
      return ENOMEM;
  }
  container_def->mounts_len = new_mounts_len;

  return 0;
}

int
build_kontain_device(char *devpath,
   runtime_spec_schema_defs_linux_device **devp,
   runtime_spec_schema_defs_linux_device_cgroup **accessp)
{
  struct stat statb;
  runtime_spec_schema_defs_linux_device *dev = NULL;
  runtime_spec_schema_defs_linux_device_cgroup *access = NULL;
  int ret = 0;

  if (stat(devpath, &statb) == 0) {
    dev = calloc(1, sizeof(runtime_spec_schema_defs_linux_device));
    if (dev == NULL) {
      return ENOMEM;
    }
    access = calloc(1, sizeof(runtime_spec_schema_defs_linux_device_cgroup));
    if (access == NULL) {
      return ENOMEM;
    }

    // Build the device
    switch (statb.st_mode & S_IFMT) {
    case S_IFBLK:
      dev->type = strdup("b");
      break;
    case S_IFCHR:
      dev->type = strdup("c");
      break;
    case S_IFIFO:
      dev->type = strdup("p");
      break;
    default:
      free(dev);
      free(access);
      return EINVAL;
      break;
    }
    dev->path = strdup(devpath);
    dev->file_mode_present = 1;
    dev->file_mode = statb.st_mode;
    dev->major_present = 1;
    dev->major = major(statb.st_rdev);
    dev->minor_present = 1;
    dev->minor = minor(statb.st_rdev);
    dev->uid_present  = 1;
    dev->uid = statb.st_uid;
    dev->gid_present = 1;
    dev->gid = statb.st_gid;

     // Build the granted access
     access->allow = 1;
     access->allow_present = 1;
     access->type = strdup(dev->type);
     access->major = dev->major;
     access->major_present = 1;
     access->minor = dev->minor;
     access->minor_present = 1;
     access->access = strdup("rwm");

     *devp = dev;
     *accessp = access;
  } else {
    ret = errno;
  }
  return ret;
}

int
add_kontain_devices(libcrun_container_t *container, const char *use_virt)
{
  runtime_spec_schema_config_schema *container_def = container->container_def;
  runtime_spec_schema_config_linux *linux = container_def->linux;
  runtime_spec_schema_defs_linux_device *dev;
  runtime_spec_schema_defs_linux_device_cgroup *access;
  int ret = ENODEV;

  if (strcmp(use_virt, "kvm") == 0) {
    ret = build_kontain_device("/dev/kvm", &dev, &access);
  } else if (strcmp(use_virt, "kkm") == 0) {
    ret = build_kontain_device("/dev/kkm", &dev, &access);
  }
  if (ret != 0) {
    return ret;
  }

  // Grow devices array
  size_t new_devices_len = linux->devices_len + 1;
  runtime_spec_schema_defs_linux_device **new_devices = realloc(linux->devices, new_devices_len * sizeof(runtime_spec_schema_defs_linux_device **));
  if (new_devices == NULL) {
    return ENOMEM;
  }
  new_devices[linux->devices_len] = dev;
  linux->devices = new_devices;
  linux->devices_len = new_devices_len;

  // Grow access array
  size_t new_res_devices_len = linux->resources->devices_len + 1;
  runtime_spec_schema_defs_linux_device_cgroup **new_res_devices = realloc(linux->resources->devices, new_res_devices_len * sizeof(runtime_spec_schema_defs_linux_device_cgroup));
  if (new_res_devices == NULL) {
    return ENOMEM;
  }
  new_res_devices[linux->resources->devices_len] = access;
  linux->resources->devices = new_res_devices;
  linux->resources->devices_len = new_res_devices_len;

  return 0;
}

int
add_kontain_config(libcrun_container_t *container)
{
  int ret;
  const char *use_virt = find_annotation(container, APP_KONTAIN_USEVIRT);
  if (use_virt == NULL) {
    libcrun_warning("Couldn't find %s annotation, using kvm", APP_KONTAIN_USEVIRT);
    use_virt = "kvm";
  }

  const char *privileged = find_annotation(container, "io.podman.annotations.privileged");

  ret = add_kontain_bind_mounts(container, privileged);
  if (ret != 0) {
    return ret;
  }

  // For docker or privileged podman, we create the /dev/kvm or kkm device.
  if (privileged == NULL || strcasecmp(privileged, "true") == 0) {
    ret = add_kontain_devices(container, use_virt);
  }
  return ret;
}
