/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
 * libocispec is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libocispec is distributed in the hope that it will be useful,
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

int libcrun_cgroup_enter (char **path, int systemd, pid_t pid, const char *id, libcrun_error_t *err);
int libcrun_cgroup_killall (char *path, libcrun_error_t *err);
int libcrun_cgroup_destroy (char *path, libcrun_error_t *err);
int libcrun_set_cgroup_resources (libcrun_container *container, char *path, libcrun_error_t *err);
#endif
