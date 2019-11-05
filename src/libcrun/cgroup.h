/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
# define CGROUP_H

# include "container.h"
# include <unistd.h>

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

int libcrun_get_cgroup_mode (libcrun_error_t *err);
int libcrun_cgroup_enter (oci_container_linux_resources *resources, int cgroup_mode, char **path, const char *cgroup_path, int manager, pid_t pid, uid_t root_uid, gid_t root_gid, const char *id, libcrun_error_t *err);
int libcrun_cgroup_killall_signal (char *path, int signal, libcrun_error_t *err);
int libcrun_cgroup_killall (char *path, libcrun_error_t *err);
int libcrun_cgroup_destroy (const char *id, char *path, int manager, libcrun_error_t *err);
int libcrun_move_process_to_cgroup (pid_t pid, char *path, libcrun_error_t *err);
int libcrun_update_cgroup_resources (int cgroup_mode, oci_container_linux_resources *resources, char *path, libcrun_error_t *err);
int libcrun_cgroups_create_symlinks (const char *target, libcrun_error_t *err);
int libcrun_cgroup_pause_unpause (const char *path, const bool pause, libcrun_error_t *err);
int libcrun_cgroup_read_pids (const char *path, pid_t **pids, libcrun_error_t *err);

typedef const char * cgroups_subsystem_t;

const cgroups_subsystem_t *libcrun_get_cgroups_subsystems ();

#endif
