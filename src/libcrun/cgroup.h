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
#ifndef CGROUP_H
#define CGROUP_H

#include "container.h"
#include <unistd.h>

#ifndef CGROUP_ROOT
#  define CGROUP_ROOT "/sys/fs/cgroup"
#endif

enum
{
  CGROUP_MODE_UNIFIED = 1,
  CGROUP_MODE_LEGACY,
  CGROUP_MODE_HYBRID
};

enum
{
  CGROUP_MANAGER_CGROUPFS = 1,
  CGROUP_MANAGER_SYSTEMD,
  CGROUP_MANAGER_DISABLED
};

struct libcrun_cgroup_args
{
  runtime_spec_schema_config_linux_resources *resources;
  json_map_string_string *annotations;
  int cgroup_mode;
  char **path;
  char **scope;
  const char *cgroup_path;
  int manager;
  pid_t pid;
  uid_t root_uid;
  gid_t root_gid;
  const char *id;
  const char *systemd_subgroup;
};

LIBCRUN_PUBLIC int libcrun_get_cgroup_mode (libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_cgroup_killall_signal (const char *path, int signal, libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_cgroup_killall (const char *path, libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_cgroup_destroy (const char *id, const char *path, const char *scope, int manager,
                                           libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_move_process_to_cgroup (pid_t pid, pid_t init_pid, char *path, libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_update_cgroup_resources (int cgroup_mode,
                                                    runtime_spec_schema_config_linux_resources *resources, char *path,
                                                    libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_cgroup_is_container_paused (const char *cgroup_path, int cgroup_mode, bool *paused,
                                                       libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_cgroup_pause_unpause (const char *path, const bool pause, libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_cgroup_read_pids (const char *path, bool recurse, pid_t **pids, libcrun_error_t *err);

int libcrun_cgroup_enter (struct libcrun_cgroup_args *args, libcrun_error_t *err);
int libcrun_cgroups_create_symlinks (int dirfd, libcrun_error_t *err);

typedef const char *cgroups_subsystem_t;

const cgroups_subsystem_t *libcrun_get_cgroups_subsystems ();

int libcrun_cgroup_has_oom (const char *path, int cgroup_mode, libcrun_error_t *err);

#endif
