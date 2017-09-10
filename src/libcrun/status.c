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
#include "status.h"
#include "utils.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <yajl/yajl_tree.h>
#include <sys/stat.h>
#include <sys/types.h>

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
  cleanup_close int fd_write = open (file, O_CREAT | O_WRONLY, 0700);
  cleanup_free char *data;
  size_t len = xasprintf (&data, "{\n    \"pid\" : %d,\n    \"cgroup-path\" : \"%s\",\n    \"rootfs\" : \"%s\",\n    \"systemd-cgroup\" : \"%s\",\n    \"bundle\" : \"%s\"\n}\n",
                          status->pid,
                          status->cgroup_path ? status->cgroup_path : "",
                          status->rootfs,
                          status->systemd_cgroup ? "true" : "false",
                          status->bundle);
  if (UNLIKELY (fd_write < 0))
    return crun_make_error (err, 0, "cannot open status file");
  if (UNLIKELY (write (fd_write, data, len) < 0))
    return crun_make_error (err, 0, "cannot write status file");
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
  yajl_tree_free (tree);
  return 0;
}

int
libcrun_status_check_directories (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *dir = NULL;
  const char *run_directory = get_run_directory (state_root);
  int ret;

  ret = crun_ensure_directory (run_directory, 0700, err);
  if (UNLIKELY (ret < 0))
    return ret;

  dir = libcrun_get_state_directory (state_root, id);
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

int
libcrun_delete_container_status (const char *state_root, const char *id, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *dir = libcrun_get_state_directory (state_root, id);
  cleanup_close int dirfd = -1;
  if (UNLIKELY (dir == NULL))
        return crun_make_error (err, 0, "cannot get state directory");
  dirfd = open (dir, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "cannot open directory '%s'", dir);

  unlinkat (dirfd, "status", 0);
  unlinkat (dirfd, "notify", 0);

  ret = rmdir (dir);
  if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "cannot rm state directory");
  return ret;
}

void
libcrun_free_container_status (libcrun_container_status_t *status)
{
  if (status->cgroup_path)
    free (status->cgroup_path);
}
