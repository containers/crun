/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#ifndef CGROUP_RESOURCES_H
#define CGROUP_RESOURCES_H

#include "container.h"
#include "cgroup.h"
#include <unistd.h>

struct default_dev_s
{
  char type;
  int major;
  int minor;
  const char *access;
};
struct default_dev_s *get_default_devices ();

int update_cgroup_resources (const char *path,
                             const char *state_root,
                             runtime_spec_schema_config_linux_resources *resources,
                             bool need_devices,
                             libcrun_error_t *err);

struct bpf_program *create_dev_bpf (runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                                    libcrun_error_t *err);

#endif
