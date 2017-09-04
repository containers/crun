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
#include <fcntl.h>
#include <yajl/yajl_tree.h>

crun_container *
libcrun_container_load (const char *path, libcrun_error_t *error)
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
get_run_directory (const char *state_root)
{
  char *root = NULL;

  if (state_root)
    root = xstrdup (state_root);
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
get_state_directory (const char *state_root, const char *id)
{
  char *ret;
  cleanup_free char *root = get_run_directory (state_root);
  xasprintf (&ret, "%s/%s", root, id);
  return ret;
}

static char *
get_state_directory_status_file (const char *state_root, const char *id)
{
  char *ret;
  cleanup_free char *root = get_run_directory (state_root);
  xasprintf (&ret, "%s/%s/status", root, id);
  return ret;
}

static int
check_directories (struct crun_run_options *opts, const char *id, libcrun_error_t *err)
{
  cleanup_free char *dir = NULL;
  const char *run_directory = get_run_directory (opts->state_root);
  int ret;

  ret = ret = crun_ensure_directory (run_directory, 0700, err);
  if (UNLIKELY (ret < 0))
    return ret;

  dir = get_state_directory (opts->state_root, id);
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

struct container_status_s
{
  pid_t pid;
};

static int
write_container_status (crun_container *container, struct crun_run_options *opts, pid_t pid, libcrun_error_t *err)
{
  cleanup_free char *file = get_state_directory_status_file (opts->state_root, opts->id);
  cleanup_close int fd_write = open (file, O_CREAT | O_WRONLY, 0700);
  cleanup_free char *data;
  size_t len = xasprintf (&data, "{\n    \"pid\" : %d\n}\n", pid);
  if (UNLIKELY (fd_write < 0))
    return crun_make_error (err, 0, "cannot open status file");
  if (UNLIKELY (write (fd_write, data, len) < 0))
    return crun_make_error (err, 0, "cannot write status file");
  return 0;
}

static int
read_container_status (struct container_status_s *status, const char *state_root, const char *id, libcrun_error_t *err)
{
  char buffer[1024];
  char err_buffer[256];
  int len;
  cleanup_free char *file = get_state_directory_status_file (state_root, id);
  cleanup_close int fd = open (file, O_RDONLY);
  yajl_val tree;

  if (UNLIKELY (fd < 0))
    return crun_make_error (err, 0, "cannot open status file");

  len = read (fd, buffer, sizeof (buffer) - 1);
  if (UNLIKELY (len < 0))
    return crun_make_error (err, 0, "cannot read from the status file");
  buffer[len] = '\0';

  tree = yajl_tree_parse (buffer, err_buffer, sizeof (err_buffer));
  if (UNLIKELY (tree == NULL))
    return crun_make_error (err, 0, "cannot parse status file");

  {
    const char *pid_path[] = { "pid", NULL };
    status->pid = strtoull (YAJL_GET_NUMBER (yajl_tree_get (tree, pid_path, yajl_t_number)), NULL, 10);
  }
  yajl_tree_free (tree);
}

int
libcrun_delete_container (const char *state_root, const char *id, int force, libcrun_error_t *err)
{
  int ret;
  cleanup_close int dirfd = -1;
  cleanup_free char *dir = get_state_directory (state_root, id);
  struct container_status_s status;
  if (UNLIKELY (dir == NULL))
        return crun_make_error (err, 0, "cannot get state directory");

  dirfd = open (dir, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "cannot open directory '%s'", dir);

  ret = read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

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

  ret = unlinkat (dirfd, "status", 0);
  if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "cannot rm status file");

  ret = rmdir (dir);
  if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "cannot rm state directory");

  return 0;
}

int
libcrun_kill_container (const char *state_root, const char *id, int signal, libcrun_error_t *err)
{
  int ret;
  struct container_status_s status;
  ret = read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = kill (status.pid, signal);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "kill container");
  return 0;
}

int
libcrun_container_run (crun_container *container, struct crun_run_options *opts, libcrun_error_t *err)
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

  ret = write_container_status (container, opts, ret, err);
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
