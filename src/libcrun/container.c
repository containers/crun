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
#include "seccomp.h"
#include <argp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/wait.h>
#include <string.h>

crun_container *
crun_container_load (const char *path, libcrun_error_t *error)
{
  crun_container *container;
  oci_container *container_def;
  cleanup_free char *oci_error = NULL;
  container_def = oci_container_parse_file (path, 0, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (error, 0, "cannot parse configuration file: '%s'", oci_error);
      return NULL;
    }

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
check_directories (struct crun_run_options *opts, const char *id, libcrun_error_t *err)
{
  cleanup_free char *dir = NULL;
  const char *run_directory = get_run_directory (opts);
  int ret;

  ret = ret = crun_ensure_directory (run_directory, 0700, err);
  if (UNLIKELY (ret < 0))
    return ret;

  dir = get_state_directory (opts, id);
  if (UNLIKELY (dir == NULL))
        return crun_make_error (err, 0, "cannot get state directory");

  ret = crun_path_exists (dir, 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (ret)
    return crun_make_error (err, 0, "container '%s' already exists", id);

  if (UNLIKELY (mkdir (dir, 0700) < 0))
    return crun_make_error (err, 0, "cannot create state directory for '%s'", id);

  return 0;
}

static void
get_uid_gid_from_def (oci_container *def, uid_t *uid, gid_t *gid)
{
  *uid = 0;
  *gid = 0;

  if (def->process->user)
    {
      if (def->process->user->uid)
        *uid = def->process->user->uid;
      if (def->process->user->gid)
        *gid = def->process->user->gid;
    }
}

static int
set_uid_gid (crun_container *container, libcrun_error_t *err)
{
  uid_t uid = container->container_uid;
  gid_t gid = container->container_gid;

  if (gid && setgid (gid) < 0)
    return crun_make_error (err, errno, "setgid");
  if (uid && setuid (uid) < 0)
    return crun_make_error (err, errno, "setuid");
  return 0;
}

struct container_entrypoint_s
{
  crun_container *container;
  struct crun_run_options *opts;
};

/* Entrypoint to the container.  */
static void
container_run (void *args)
{
  struct container_entrypoint_s *entrypoint_args = args;
  crun_container *container = entrypoint_args->container;
  struct crun_run_options *opts = entrypoint_args->opts;
  libcrun_error_t err = NULL;
  int ret;
  size_t i;
  oci_container *def = container->container_def;
  cleanup_free char *rootfs = NULL;

  get_uid_gid_from_def (container->container_def,
                        &container->container_uid,
                        &container->container_gid);

  if (container->unshare_flags & CLONE_NEWUSER)
    {
      ret = libcrun_set_usernamespace (container, &err);
      if (UNLIKELY (ret < 0))
        goto out;
    }

  rootfs = realpath (def->root->path, NULL);
  if (UNLIKELY (rootfs == NULL))
    {
      ret = crun_make_error (&err, errno, "realpath");
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

  ret = set_uid_gid (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  if (def->process->cwd)
    if (UNLIKELY (chdir (def->process->cwd) < 0))
      {
        ret = crun_make_error (&err, errno, "chdir");
        goto out;
      }

  ret = libcrun_set_seccomp (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  if (clearenv ())
    {
      ret = crun_make_error (&err, 0, "clearenv");
      goto out;
    }

  for (i = 0; i < def->process->env_len; i++)
    if (putenv (def->process->env[i]) < 0)
      {
        ret = crun_make_error (&err, 0, "putenv '%s'", def->process->env[i]);
        goto out;
      }

  if (UNLIKELY (execvp (def->process->args[0], def->process->args) < 0))
    {
      ret = crun_make_error (&err, errno, "exec the container process");
      goto out;
    }

 out:
  error (EXIT_FAILURE, err->status, "%s", err->msg);
}

static int
delete_container (crun_container *container, struct crun_run_options *opts, int force, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *dir = get_state_directory (opts, opts->id);
  if (UNLIKELY (dir == NULL))
        return crun_make_error (err, 0, "cannot get state directory");

  ret = rmdir (dir);
  if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "cannot rm state directory");

  return 0;
}

int
crun_container_run (crun_container *container, struct crun_run_options *opts, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;
  int detach = opts->detach;
  struct container_entrypoint_s container_args = {.container = container, .opts = opts};

  if (UNLIKELY (def->root == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'root' block specified");
  if (UNLIKELY (def->process == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'process' block specified");
  if (UNLIKELY (def->linux == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'linux' block specified");
  if (UNLIKELY (def->mounts == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'mounts' block specified");

  ret = check_directories (opts, opts->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (detach)
    {
      ret = fork ();
      if (ret < 0)
        return crun_make_error (err, 0, "fork");
      if (ret)
        return 0;

      ret = detach_process ();
      if (ret < 0)
        return crun_make_error (err, errno, "detach process");
    }

  ret = libcrun_run_container (container, opts->detach, container_run, &container_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (opts->detach)
    return ret;

  while (1)
    {
      int status;
      int r = waitpid (ret, &status, 0);
      if (r < 0)
        {
          if (errno == EINTR)
            continue;
          return crun_make_error (err, errno, "waitpid");
        }
      if (WIFEXITED (status) || WIFSIGNALED (status))
        {
          delete_container (container, opts, 1, err);
          return WEXITSTATUS (status);
        }
    }

  return 0;
}
