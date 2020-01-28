/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#define _GNU_SOURCE

#include <config.h>
#include "status.h"
#include "utils.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <yajl/yajl_tree.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>

static char *
get_run_directory (const char *state_root)
{
  int ret;
  char *root = NULL;
  libcrun_error_t err = NULL;

  if (state_root)
    root = xstrdup (state_root);
  if (root == NULL)
    {
      const char *runtime_dir = getenv ("XDG_RUNTIME_DIR");
      if (runtime_dir && runtime_dir[0] != '\0')
        xasprintf (&root, "%s/crun", runtime_dir);
    }
  if (root == NULL)
    root = xstrdup ("/run/crun");

  ret = crun_ensure_directory (root, 0700, false, &err);
  if (UNLIKELY (ret < 0))
    crun_error_release (&err);
  return root;
}

char *
libcrun_get_state_directory (const char *state_root, const char *id)
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

int
libcrun_write_container_status (const char *state_root, const char *id, libcrun_container_status_t *status, libcrun_error_t *err)
{
  cleanup_free char *file = get_state_directory_status_file (state_root, id);
  cleanup_free char *file_tmp = NULL;
  size_t len;
  cleanup_close int fd_write = -1;
  cleanup_free char *data;

  xasprintf (&file_tmp, "%s.tmp", file);
  fd_write = open (file_tmp, O_CREAT | O_WRONLY, 0700);
  if (UNLIKELY (fd_write < 0))
    return crun_make_error (err, 0, "cannot open status file");

  len = xasprintf (&data, "{\n    \"pid\" : %d,\n    \"cgroup-path\" : \"%s\",\n    \"rootfs\" : \"%s\",\n    \"systemd-cgroup\" : \"%s\",\n    \"bundle\" : \"%s\",\n    \"created\" : \"%s\",\n    \"detached\" : \"%s\"\n}\n",
                   status->pid,
                   status->cgroup_path ? status->cgroup_path : "",
                   status->rootfs,
                   status->systemd_cgroup ? "true" : "false",
                   status->bundle,
                   status->created,
                   status->detached ? "true" : "false");
  if (UNLIKELY (write (fd_write, data, len) < 0))
    return crun_make_error (err, 0, "cannot write status file");

  close_and_reset (&fd_write);

  if (UNLIKELY (rename (file_tmp, file) < 0))
    return crun_make_error (err, 0, "cannot rename status file");

  return 0;
}

int
libcrun_read_container_status (libcrun_container_status_t *status, const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  char err_buffer[256];
  int ret;
  cleanup_free char *file = get_state_directory_status_file (state_root, id);
  yajl_val tree;

  ret = read_all_file (file, &buffer, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  tree = yajl_tree_parse (buffer, err_buffer, sizeof (err_buffer));
  if (UNLIKELY (tree == NULL))
    return crun_make_error (err, 0, "cannot parse status file");

  {
    const char *pid_path[] = { "pid", NULL };
    status->pid = strtoull (YAJL_GET_NUMBER (yajl_tree_get (tree, pid_path, yajl_t_number)), NULL, 10);
  }
  {
    const char *cgroup_path[] = { "cgroup-path", NULL };
    status->cgroup_path = xstrdup (YAJL_GET_STRING (yajl_tree_get (tree, cgroup_path, yajl_t_string)));
  }
  {
    const char *rootfs[] = { "rootfs", NULL };
    status->rootfs = xstrdup (YAJL_GET_STRING (yajl_tree_get (tree, rootfs, yajl_t_string)));
  }
  {
    const char *bundle[] = { "systemd-cgroup", NULL };
    status->systemd_cgroup = YAJL_IS_TRUE (yajl_tree_get (tree, bundle, yajl_t_true));
  }
  {
    const char *bundle[] = { "bundle", NULL };
    status->bundle = xstrdup (YAJL_GET_STRING (yajl_tree_get (tree, bundle, yajl_t_string)));
  }
  {
    const char *created[] = { "created", NULL };
    status->created = xstrdup (YAJL_GET_STRING (yajl_tree_get (tree, created, yajl_t_string)));
  }
  {
    const char *bundle[] = { "detached", NULL };
    status->detached = YAJL_IS_TRUE (yajl_tree_get (tree, bundle, yajl_t_true));
  }
  yajl_tree_free (tree);
  return 0;
}

int
libcrun_status_check_directories (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *dir = NULL;
  cleanup_free char *run_directory = get_run_directory (state_root);
  int ret;

  ret = crun_ensure_directory (run_directory, 0700, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  dir = libcrun_get_state_directory (state_root, id);
  if (UNLIKELY (dir == NULL))
        return crun_make_error (err, 0, "cannot get state directory");

  ret = crun_path_exists (dir, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (ret)
    return crun_make_error (err, 0, "container `%s` already exists", id);

  if (UNLIKELY (mkdir (dir, 0700) < 0))
    return crun_make_error (err, 0, "cannot create state directory for `%s`", id);

  return 0;
}

int
libcrun_container_delete_status (const char *state_root, const char *id, libcrun_error_t *err)
{
  int ret;
  cleanup_dir DIR *d = NULL;
  cleanup_close int rundir_dfd = -1;
  cleanup_close int dfd = -1;
  cleanup_free char *dir = NULL;

  dir = get_run_directory (state_root);
  if (UNLIKELY (dir == NULL))
        return crun_make_error (err, 0, "cannot get state directory");

  rundir_dfd = open (dir, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (rundir_dfd < 0))
    return crun_make_error (err, errno, "cannot open run directory `%s`", dir);

  dfd = openat (rundir_dfd, id, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dfd < 0))
    return crun_make_error (err, errno, "cannot open directory '%s/%s'", dir, id);

  d = fdopendir (dfd);
  if (d == NULL)
    return crun_make_error (err, errno, "cannot open directory `%s`", dir);

  /* Now d owns the file descriptor.  */
  dfd = -1;

  struct dirent *de;
  while (de = readdir (d))
    {
      /* Ignore errors here and keep deleting, the final unlinkat (AT_REMOVEDIR) will fail anyway.  */
      ret = unlinkat (dirfd (d), de->d_name, 0);
      if (ret < 0)
        unlinkat (dirfd (d), de->d_name, AT_REMOVEDIR);
    }
  ret = unlinkat (rundir_dfd, id, AT_REMOVEDIR);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot rm state directory '%s/%s'", dir, id);

  return 0;
}

void
libcrun_free_container_status (libcrun_container_status_t *status)
{
  if (status == NULL)
    return;
  free (status->cgroup_path);
  free (status->bundle);
  free (status->rootfs);
  free (status->created);
}

int
libcrun_get_containers_list (libcrun_container_list_t **ret, const char *state_root, libcrun_error_t *err)
{
  libcrun_container_list_t *tmp = NULL;
  cleanup_free char *path = get_run_directory (state_root);
  cleanup_dir DIR *dir;
  cleanup_free char *run_directory = get_run_directory (state_root);

  *ret = NULL;
  dir = opendir (path);
  if (UNLIKELY (dir == NULL))
      return crun_make_error (err, errno, "cannot opendir `%s`", path);

  struct dirent *next;
  while (next = readdir (dir))
    {
      int exists;
      cleanup_free char *status_file = NULL;

      libcrun_container_list_t *next_container;

      if (next->d_name[0] == '.')
        continue;

      xasprintf (&status_file, "%s/%s/status", run_directory, next->d_name);
      exists = crun_path_exists (status_file, err);
      if (exists < 0)
       {
         libcrun_free_containers_list (tmp);
         return exists;
       }

      if (!exists)
        continue;

      next_container = xmalloc (sizeof (libcrun_container_list_t));
      next_container->name = xstrdup (next->d_name);
      next_container->next = tmp;
      tmp = next_container;
    }
  *ret = tmp;
  return 0;
}

void
libcrun_free_containers_list (libcrun_container_list_t *list)
{
  libcrun_container_list_t *next;
  while (list)
    {
      next = list->next;
      free (list->name);
      free (list);
      list = next;
    }
}

int
libcrun_is_container_running (libcrun_container_status_t *status, libcrun_error_t *err)
{
  int ret;

  ret = kill (status->pid, 0);
  if (UNLIKELY (ret < 0) && errno != ESRCH)
    return crun_make_error (err, errno, "kill");

  if (ret == 0)
    return 1;

  return 0;
}

int
libcrun_status_create_exec_fifo (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *state_dir = libcrun_get_state_directory (state_root, id);
  cleanup_free char *fifo_path;
  int ret, fd = -1;
  xasprintf (&fifo_path, "%s/exec.fifo", state_dir);
  ret = mkfifo (fifo_path, 0600);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mkfifo");

  fd = open (fifo_path, O_NONBLOCK);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "cannot open pipe `%s`", fifo_path);

  return fd;
}

int
libcrun_status_write_exec_fifo (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *state_dir = libcrun_get_state_directory (state_root, id);
  cleanup_free char *fifo_path;
  char buffer[1] = {0, };
  int ret;
  cleanup_close int fd = -1;

  xasprintf (&fifo_path, "%s/exec.fifo", state_dir);

  fd = open (fifo_path, O_WRONLY);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "cannot open `%s`", fifo_path);

  ret = unlink (fifo_path);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "unlink `%s`", fifo_path);

  ret = TEMP_FAILURE_RETRY (write (fd, buffer, 1));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read from exec.fifo");

  return strtoll (buffer, NULL, 10);
}

int
libcrun_status_has_read_exec_fifo (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *state_dir = libcrun_get_state_directory (state_root, id);
  cleanup_free char *fifo_path;

  xasprintf (&fifo_path, "%s/exec.fifo", state_dir);

  return crun_path_exists (fifo_path, err);
}
