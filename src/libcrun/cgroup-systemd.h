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
#ifndef CGROUP_SYSTEMD_H
#define CGROUP_SYSTEMD_H

#include "container.h"
#include <unistd.h>

#ifdef HAVE_SYSTEMD
extern int parse_sd_array (char *s, char **out, char **next, libcrun_error_t *err);

extern int cpuset_string_to_bitmask (const char *str, char **out, size_t *out_size, libcrun_error_t *err);

extern char *get_cgroup_scope_path (const char *cgroup_path, const char *scope);
#endif

extern struct libcrun_cgroup_manager cgroup_manager_systemd;

#endif
