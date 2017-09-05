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
#include "seccomp.h"
#include <argp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#include "status.h"
#include "linux.h"
#include "cgroup.h"

libcrun_container *
libcrun_container_load (const char *path, libcrun_error_t *error)
{
  libcrun_container *container;
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
set_uid_gid (libcrun_container *container, libcrun_error_t *err)
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
  libcrun_container *container;
  struct libcrun_run_options *opts;
};

/* Entrypoint to the container.  */
static void
container_run (void *args)
{
  struct container_entrypoint_s *entrypoint_args = args;
  libcrun_container *container = entrypoint_args->container;
  libcrun_error_t err = NULL;
  int ret;
  size_t i;
  oci_container *def = container->container_def;
  cleanup_free char *rootfs = NULL;

  get_uid_gid_from_def (container->container_def,
                        &container->container_uid,
                        &container->container_gid);


  ret = libcrun_set_usernamespace (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

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

int
libcrun_delete_container (const char *state_root, const char *id, int force, libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  if (force)
    {
      /* When --force is used, kill the container.  */
      kill (status.pid, 9);
    }
  else
    {

      ret = kill (status.pid, 0);
      if (ret == 0)
        return crun_make_error (err, 0, "the container '%s' is still running", id);
      if (UNLIKELY (ret < 0 && errno != ESRCH))
        return crun_make_error (err, errno, "signaling the container");
    }

  if (status.cgroup_path)
    {
      ret = libcrun_cgroup_destroy (status.cgroup_path, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  libcrun_free_container_status (&status);

 exit:
  return libcrun_delete_container_status (state_root, id, err);
}

int
libcrun_kill_container (const char *state_root, const char *id, int signal, libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status;
  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = kill (status.pid, signal);

  libcrun_free_container_status (&status);

  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "kill container");
  return 0;
}

static int
write_container_status (libcrun_container *container, struct libcrun_run_options *opts, pid_t pid, char *cgroup_path, libcrun_error_t *err)
{
  libcrun_container_status_t status = {.pid = pid, .cgroup_path = cgroup_path};
  return libcrun_write_container_status (opts->state_root, opts->id, &status, err);
}

int
libcrun_container_run (libcrun_container *container, struct libcrun_run_options *opts, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;
  pid_t pid;
  int detach = opts->detach;
  cleanup_free char *cgroup_path = NULL;
  struct container_entrypoint_s container_args = {.container = container, .opts = opts};

  if (UNLIKELY (def->root == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'root' block specified");
  if (UNLIKELY (def->process == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'process' block specified");
  if (UNLIKELY (def->linux == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'linux' block specified");
  if (UNLIKELY (def->mounts == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'mounts' block specified");

  ret = libcrun_status_check_directories (opts->state_root, opts->id, err);
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

  pid = libcrun_run_container (container, opts->detach, container_run, &container_args, err);
  if (UNLIKELY (pid < 0))
    return pid;

  ret = libcrun_cgroup_enter (&cgroup_path, opts->systemd_cgroup, pid, opts->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = write_container_status (container, opts, pid, cgroup_path, err);
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
          libcrun_delete_container (opts->state_root, opts->id, 1, err);
          return WEXITSTATUS (status);
        }
    }

  return 0;
}
