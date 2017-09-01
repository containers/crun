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
#include <sched.h>
#include <sys/wait.h>
#include <string.h>

crun_container *
crun_container_load (const char *path, char **error)
{
  crun_container *container;
  oci_container *container_def;

  container_def = oci_container_parse_file (path, 0, error);
  if (container_def == NULL)
    return NULL;

  container = xmalloc (sizeof (*container));
  memset (container, 0, sizeof (*container));
  container->container_def = container_def;

  container->host_uid = getuid ();
  container->host_gid = getgid ();

  return container;
}

static char *
get_run_directory (struct crun_run_options *opts)
{
  char *root = NULL;

  if (opts->state_root)
    root = xstrdup (opts->state_root);
  if (root == NULL)
    {
      const char *runtime_dir = getenv ("XDG_RUNTIME_DIR");
      if (runtime_dir)
        xasprintf (&root, "%s/crun", runtime_dir);
    }
  if (root == NULL)
    root = xstrdup ("/run/crun");

  return root;
}

static char *
get_state_directory (struct crun_run_options *opts, const char *id)
{
  char *ret;
  cleanup_free char *root = get_run_directory (opts);
  xasprintf (&ret, "%s/%s", root, id);
  return ret;
}

static int
check_directories (struct crun_run_options *opts, const char *id, char **err)
{
  cleanup_free char *dir = NULL;
  const char *run_directory = get_run_directory (opts);
  int ret;

  ret = ret = crun_ensure_directory (run_directory, 0700, err);
  if (UNLIKELY (ret < 0))
    return ret;

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

  return 0;
}

static void
container_load (crun_container *container, struct crun_run_options *opts)
{
  char *err = NULL;
  int ret;
  oci_container *def = container->container_def;
  cleanup_free char *rootfs = NULL;

  if (container->unshare_flags & CLONE_NEWUSER)
    {
      ret = libcrun_set_usernamespace (container, &err);
      if (UNLIKELY (ret < 0))
        goto out;
    }

  rootfs = realpath (def->root->path, NULL);
  if (UNLIKELY (rootfs == NULL))
    {
      ret = crun_static_error (&err, errno, "realpath");
      goto out;
    }

  ret = libcrun_set_mounts (container, rootfs, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  ret = libcrun_set_selinux_exec_label (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  ret = libcrun_set_caps (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  ret = libcrun_set_rlimits (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  if (def->process->cwd)
    if (UNLIKELY (chdir (def->process->cwd) < 0))
      {
        ret = crun_static_error (&err, errno, "chdir");
        goto out;
      }

  execvpe (def->process->args[0], def->process->args, def->process->env);
 out:
  error (EXIT_FAILURE, -(ret + 1), "%s", err);
}

int
crun_container_run (crun_container *container, struct crun_run_options *opts, char **err)
{
  oci_container *def = container->container_def;
  int ret;
  int detach = opts->detach;

  if (UNLIKELY (def->root == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'root' block specified");
  if (UNLIKELY (def->process == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'process' block specified");
  if (UNLIKELY (def->linux == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'linux' block specified");
  if (UNLIKELY (def->mounts == NULL))
    return crun_static_error (err, 0, "invalid config file, no 'mounts' block specified");

  ret = check_directories (opts, opts->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (detach)
    {
      ret = fork ();
      if (ret < 0)
        return crun_static_error (err, 0, "fork");
      if (ret)
        return 0;

      ret = detach_process ();
      if (ret < 0)
        return crun_static_error (err, errno, "detach process");
    }

  ret = libcrun_set_namespaces (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* We need to fork to join the new PID namespace.  */
  ret = fork ();
  if (ret < 0)
    return crun_static_error (err, errno, "fork to new PID namespace");
  if (ret == 0)
    {
      container_load (container, opts);
      _exit (1);
    }

  while (1)
    {
      int status;
      int r = waitpid (ret, &status, 0);
      if (r < 0)
        {
          if (errno == EINTR)
            continue;
          return crun_static_error (err, errno, "waitpid");
        }
      if (WIFEXITED (status) || WIFSIGNALED (status))
        return WEXITSTATUS (status);
    }

  return 0;
}
