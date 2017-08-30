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

#ifndef CONTAINER_H
# define CONTAINER_H

# include <config.h>
# include <oci_runtime_spec.h>

struct crun_container_s
{
  /* Container parsed from the runtime json file.  */
  oci_container *container_def;
};

struct crun_run_options
{
  char *id;
  char *console_socket;
  char *pid_file;
  int preserve_fds;

  int detach : 1;
  int no_subreaper: 1;
  int no_new_keyring : 1;
};

typedef struct crun_container_s crun_container;

crun_container *crun_container_load (const char *path, char **error);

int crun_container_run (crun_container *container, struct crun_run_options *opts, char **error);

#endif
