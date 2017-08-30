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
#define _GNU_SOURCE

#include <config.h>
#include "container.h"
#include "utils.h"
#include "linux.h"
#include <argp.h>
#include <unistd.h>

crun_container *
crun_container_load (const char *path, char **error)
{
  crun_container *container;
  oci_container *container_def;

  container_def = oci_container_parse_file (path, 0, error);
  if (container_def == NULL)
    return NULL;

  container = xmalloc (sizeof (*container));
  container->container_def = container_def;

  return container;
}

int
crun_container_run (crun_container *container, struct crun_run_options *opts, char **err)
{
  oci_container *def = container->container_def;
  int ret;
  if (UNLIKELY (def->root == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'root' block specified");
  if (UNLIKELY (def->process == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'process' block specified");
  if (UNLIKELY (def->linux == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'linux' block specified");

  ret = libcrun_set_namespaces (def, err);
  if (ret < 0)
    return ret;

  if (UNLIKELY (chroot (def->root->path) < 0))
    return crun_static_error (err, errno, "chroot");

  execvpe (def->process->args[0], def->process->args, def->process->env);
  return 0;
}
