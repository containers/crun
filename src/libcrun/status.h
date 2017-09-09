/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
 * libocispec is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libocispec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef STATUS_H
# define STATUS_H

# include <config.h>
# include <oci_runtime_spec.h>
# include "error.h"
# include "container.h"

struct libcrun_container_status_s
{
  pid_t pid;
  char *bundle;
  char *rootfs;
  char *cgroup_path;
};
typedef struct libcrun_container_status_s libcrun_container_status_t;

void libcrun_free_container_status (libcrun_container_status_t *status);
int libcrun_write_container_status (const char *state_root, const char *id, libcrun_container_status_t *status, libcrun_error_t *err);
int libcrun_read_container_status (libcrun_container_status_t *status, const char *state_root, const char *id, libcrun_error_t *err);
int libcrun_status_check_directories (const char *state_root, const char *id, libcrun_error_t *err);
int libcrun_delete_container_status (const char *state_root, const char *id, libcrun_error_t *err);

#endif
