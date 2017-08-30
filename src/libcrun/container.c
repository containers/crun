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
#include <sys/stat.h>
#include <sys/types.h>

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

static const char *
get_run_directory (struct crun_run_options *opts)
{
  const char *root = opts->state_root;
  if (root == NULL)
    root = "/run/crun";

  return root;
}

static char *
get_state_directory (struct crun_run_options *opts, const char *id)
{
  char *ret;
  const char *root = get_run_directory (opts);
  if (UNLIKELY (asprintf (&ret, "%s/%s", root, id) < 0))
    OOM ();
  return ret;
}

static char *
get_rootfs_directory (struct crun_run_options *opts, const char *id)
{
  char *ret;
  const char *root = get_run_directory (opts);
  if (UNLIKELY (asprintf (&ret, "%s/%s/rootfs", root, id) < 0))
    OOM ();
  return ret;
}

static int
check_directories (char **rootfs, struct crun_run_options *opts, const char *id, char **err)
{
  cleanup_free char *dir = NULL;
  const char *run_directory = get_run_directory (opts);
  int ret;

  *rootfs = NULL;
  ret = crun_path_exists (run_directory, 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (ret == 0 && UNLIKELY (mkdir (run_directory, 0700) < 0))
    return crun_static_error (err, 0, "cannot create directory '%s'", run_directory);

  dir = get_state_directory (opts, id);
  if (UNLIKELY (dir == NULL))
        return crun_static_error (err, 0, "cannot get state directory");

  ret = crun_path_exists (dir, 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (ret)
    return crun_static_error (err, 0, "container '%s' already exists", id);

  if (UNLIKELY (mkdir (dir, 0700) < 0))
    return crun_static_error (err, 0, "cannot create state directory for '%s'", id);

  *rootfs = get_rootfs_directory (opts, id);
  if (UNLIKELY (mkdir (*rootfs, 0700) < 0))
    {
      free (*rootfs);
      *rootfs = NULL;
      return crun_static_error (err, 0, "cannot create rootfs directory for '%s'", id);
    }
  return 0;
}

int
crun_container_run (crun_container *container, struct crun_run_options *opts, char **err)
{
  oci_container *def = container->container_def;
  int ret;
  cleanup_free char *rootfs = NULL;
  if (UNLIKELY (def->root == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'root' block specified");
  if (UNLIKELY (def->process == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'process' block specified");
  if (UNLIKELY (def->linux == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'linux' block specified");
  if (UNLIKELY (def->mounts == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'mounts' block specified");

  ret = libcrun_set_namespaces (def, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = check_directories (&rootfs, opts, opts->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_mounts (def, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (UNLIKELY (chroot (rootfs) < 0))
    return crun_static_error (err, errno, "chroot");

  if (def->process->cwd)
    if (UNLIKELY (chdir (def->process->cwd) < 0))
    return crun_static_error (err, errno, "chdir");

  execvpe (def->process->args[0], def->process->args, def->process->env);
  return 0;
}
