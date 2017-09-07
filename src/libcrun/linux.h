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
#ifndef LINUX_H
# define LINUX_H
# include <config.h>
# include <stdio.h>
# include <stdlib.h>
# include <error.h>
# include <errno.h>
# include <argp.h>
# include <oci_runtime_spec.h>
# include "container.h"

typedef void (*container_entrypoint) (void *args);

pid_t libcrun_run_container (libcrun_container *container,
                             int detach,
                             container_entrypoint entrypoint,
                             void *args,
                             libcrun_error_t *err);
int libcrun_set_mounts (libcrun_container *container, const char *rootfs, libcrun_error_t *err);
int libcrun_set_usernamespace (libcrun_container *container, libcrun_error_t *err);
int libcrun_set_caps (libcrun_container *container, libcrun_error_t *err);
int libcrun_set_rlimits (libcrun_container *container, libcrun_error_t *err);
int libcrun_set_selinux_exec_label (libcrun_container *container, libcrun_error_t *err);
int libcrun_set_hostname (libcrun_container *container, libcrun_error_t *err);
int libcrun_set_oom (libcrun_container *container, libcrun_error_t *err);
int libcrun_set_sysctl (libcrun_container *container, libcrun_error_t *err);
int libcrun_set_terminal (libcrun_container *container, libcrun_error_t *err);

#endif
