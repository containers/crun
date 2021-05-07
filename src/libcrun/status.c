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

#define YAJL_STR(x) ((const unsigned char *) (x))

struct pid_stat
{
  char state;
  unsigned long long starttime;
};

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
        {
          ret = append_paths (&root, &err, runtime_dir, "crun", NULL);
          if (UNLIKELY (ret < 0))
            {
              crun_error_release (&err);
              return NULL;
            }
        }
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
  int ret;
  char *path;
  libcrun_error_t *err = NULL;
  cleanup_free char *root = get_run_directory (state_root);

  ret = append_paths (&path, err, root, id, NULL);
  if (UNLIKELY (ret < 0))
    {
      crun_error_release (err);
      return NULL;
    }

  return path;
}

static char *
get_state_directory_status_file (const char *state_root, const char *id)
{
  cleanup_free char *root = get_run_directory (state_root);
  libcrun_error_t *err = NULL;
  char *path = NULL;
  int ret;

  ret = append_paths (&path, err, root, id, "status", NULL);
  if (UNLIKELY (ret < 0))
    {
      crun_error_release (err);
      return NULL;
    }

  return path;
}

static int
read_pid_stat (pid_t pid, struct pid_stat *st, libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  cleanup_close int fd = -1;
  char pid_stat_file[64];
  char *it, *s;
  int i, ret;

  sprintf (pid_stat_file, "/proc/%d/stat", pid);

  fd = open (pid_stat_file, O_RDONLY);
  if (fd < 0)
    {
      /* The process already exited.  */
      if (errno == ENOENT || errno == ESRCH)
        {
          memset (st, 0, sizeof (*st));
          return 0;
        }
      return crun_make_error (err, errno, "open state file %s", pid_stat_file);
    }

  ret = read_all_fd (fd, pid_stat_file, &buffer, NULL, err);
  if (ret < 0)
    {
      st->starttime = 0;
      st->state = 'X';
      /* The process already exited.  */
      libcrun_error_release (err);
      return 0;
    }

  s = NULL;

  /* Skip the first two arguments.  */
  for (it = buffer; it; it = strchr (it + 1, ')'))
    s = it + 1;

  if (s)
    while (*s == ' ')
      s++;

  if (s == NULL || *s == '\0')
    return crun_make_error (err, 0, "could not read process state");

  st->state = *s;

  /* Seek to the starttime argument.  */
  for (it = s + 1, i = 0; i < 19 && it != NULL; i++, it = strchr (it, ' ') + 1)
    ;

  if (it == NULL || i != 19)
    return crun_make_error (err, 0, "could not read process start time");

  errno = 0;
  st->starttime = strtoull (it, NULL, 10);
  if (errno != 0)
    return crun_make_error (err, errno, "parse process start time");

  return 0;
}

int
libcrun_write_container_status (const char *state_root, const char *id, libcrun_container_status_t *status,
                                libcrun_error_t *err)
{
  int r, ret;
  cleanup_free char *file = get_state_directory_status_file (state_root, id);
  cleanup_free char *file_tmp = NULL;
  size_t len;
  cleanup_close int fd_write = -1;
  const unsigned char *buf = NULL;
  struct pid_stat st;
  const char *tmp;
  yajl_gen gen = NULL;

  ret = read_pid_stat (status->pid, &st, err);
  if (UNLIKELY (ret < 0))
    return ret;

  status->process_start_time = st.starttime;

  xasprintf (&file_tmp, "%s.tmp", file);
  fd_write = open (file_tmp, O_CREAT | O_WRONLY, 0700);
  if (UNLIKELY (fd_write < 0))
    return crun_make_error (err, errno, "cannot open status file");

  gen = yajl_gen_alloc (NULL);
  if (gen == NULL)
    return crun_make_error (err, 0, "yajl_gen_alloc failed");

  yajl_gen_config (gen, yajl_gen_beautify, 1);
  yajl_gen_config (gen, yajl_gen_validate_utf8, 1);

  r = yajl_gen_map_open (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("pid"), strlen ("pid"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_integer (gen, status->pid);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("process-start-time"), strlen ("process-start-time"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_integer (gen, status->process_start_time);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("cgroup-path"), strlen ("cgroup-path"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  tmp = status->cgroup_path ? status->cgroup_path : "";
  r = yajl_gen_string (gen, YAJL_STR (tmp), strlen (tmp));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("scope"), strlen ("scope"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  tmp = status->scope ? status->scope : "";
  r = yajl_gen_string (gen, YAJL_STR (tmp), strlen (tmp));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("rootfs"), strlen ("rootfs"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR (status->rootfs), strlen (status->rootfs));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("systemd-cgroup"), strlen ("systemd-cgroup"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_bool (gen, status->systemd_cgroup);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("bundle"), strlen ("bundle"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR (status->bundle), strlen (status->bundle));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("created"), strlen ("created"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR (status->created), strlen (status->created));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("detached"), strlen ("detached"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_bool (gen, status->detached);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("external_descriptors"), strlen ("external_descriptors"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR (status->external_descriptors), strlen (status->external_descriptors));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_map_close (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_get_buf (gen, &buf, &len);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  if (UNLIKELY (safe_write (fd_write, buf, (ssize_t) len) < 0))
    {
      ret = crun_make_error (err, errno, "cannot write status file");
      goto exit;
    }

  close_and_reset (&fd_write);

  if (UNLIKELY (rename (file_tmp, file) < 0))
    {
      ret = crun_make_error (err, errno, "cannot rename status file");
      goto exit;
    }

exit:
  if (gen)
    yajl_gen_free (gen);

  return ret;

yajl_error:
  if (gen)
    yajl_gen_free (gen);

  return yajl_error_to_crun_error (r, err);
}

int
libcrun_read_container_status (libcrun_container_status_t *status, const char *state_root, const char *id,
                               libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  char err_buffer[256];
  int ret;
  cleanup_free char *file = get_state_directory_status_file (state_root, id);
  yajl_val tree, tmp;

  ret = read_all_file (file, &buffer, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  tree = yajl_tree_parse (buffer, err_buffer, sizeof (err_buffer));
  if (UNLIKELY (tree == NULL))
    return crun_make_error (err, 0, "cannot parse status file: %s", err_buffer);

  {
    const char *pid_path[] = { "pid", NULL };
    tmp = yajl_tree_get (tree, pid_path, yajl_t_number);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'pid' missing in %s", file);
    status->pid = strtoull (YAJL_GET_NUMBER (tmp), NULL, 10);
  }
  {
    const char *process_start_time_path[] = { "process-start-time", NULL };
    tmp = yajl_tree_get (tree, process_start_time_path, yajl_t_number);
    if (UNLIKELY (tmp == NULL))
      status->process_start_time = 0; /* backwards compatibility */
    else
      status->process_start_time = strtoull (YAJL_GET_NUMBER (tmp), NULL, 10);
  }
  {
    const char *cgroup_path[] = { "cgroup-path", NULL };
    tmp = yajl_tree_get (tree, cgroup_path, yajl_t_string);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'cgroup-path' missing in %s", file);
    status->cgroup_path = xstrdup (YAJL_GET_STRING (tmp));
  }
  {
    const char *scope[] = { "scope", NULL };
    tmp = yajl_tree_get (tree, scope, yajl_t_string);
    status->scope = tmp ? xstrdup (YAJL_GET_STRING (tmp)) : NULL;
  }
  {
    const char *rootfs[] = { "rootfs", NULL };
    tmp = yajl_tree_get (tree, rootfs, yajl_t_string);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'rootfs' missing in %s", file);
    status->rootfs = xstrdup (YAJL_GET_STRING (tmp));
  }
  {
    const char *systemd_cgroup[] = { "systemd-cgroup", NULL };
    status->systemd_cgroup = YAJL_IS_TRUE (yajl_tree_get (tree, systemd_cgroup, yajl_t_true));
  }
  {
    const char *bundle[] = { "bundle", NULL };
    tmp = yajl_tree_get (tree, bundle, yajl_t_string);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'bundle' missing in %s", file);
    status->bundle = xstrdup (YAJL_GET_STRING (tmp));
  }
  {
    const char *created[] = { "created", NULL };
    tmp = yajl_tree_get (tree, created, yajl_t_string);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'created' missing in %s", file);
    status->created = xstrdup (YAJL_GET_STRING (tmp));
  }
  {
    const char *detached[] = { "detached", NULL };
    status->detached = YAJL_IS_TRUE (yajl_tree_get (tree, detached, yajl_t_true));
  }
  {
    const char *external[] = { "external_descriptors", NULL };
    const unsigned char *buf = NULL;
    yajl_gen gen = NULL;
    size_t buf_len;

    gen = yajl_gen_alloc (NULL);
    if (gen == NULL)
      return crun_make_error (err, errno, "yajl_gen_alloc");
    yajl_gen_array_open (gen);

    tmp = yajl_tree_get (tree, external, yajl_t_array);
    if (tmp && YAJL_IS_ARRAY (tmp))
      {
        size_t len = tmp->u.array.len;
        size_t i;
        for (i = 0; i < len; ++i)
          {
            yajl_val s = tmp->u.array.values[i];
            if (s && YAJL_IS_STRING (s))
              {
                char *str = YAJL_GET_STRING (s);
                yajl_gen_string (gen, YAJL_STR (str), strlen (str));
              }
          }
      }
    yajl_gen_array_close (gen);
    yajl_gen_get_buf (gen, &buf, &buf_len);
    if (buf)
      status->external_descriptors = xstrdup ((const char *) buf);
    yajl_gen_free (gen);
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

static int
rmdirfd (const char *namedir, int fd, libcrun_error_t *err)
{
  int ret;
  cleanup_dir DIR *d = NULL;
  struct dirent *de;
  cleanup_close int fd_cleanup = fd;

  d = fdopendir (fd);
  if (d == NULL)
    return crun_make_error (err, errno, "cannot open directory `%s`", namedir);

  /* Now D owns FD. */
  fd_cleanup = -1;

  for (de = readdir (d); de; de = readdir (d))
    {
      if ((strcmp (de->d_name, ".") == 0) || (strcmp (de->d_name, "..") == 0))
        continue;

      /* Ignore errors here and keep deleting, the final unlinkat (AT_REMOVEDIR) will fail anyway.  */
      ret = unlinkat (dirfd (d), de->d_name, 0);
      if (ret < 0)
        {
          ret = unlinkat (dirfd (d), de->d_name, AT_REMOVEDIR);
          if (ret < 0 && errno == ENOTEMPTY)
            {
              cleanup_close int cfd = -1;

              cfd = openat (dirfd (d), de->d_name, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
              if (UNLIKELY (cfd < 0))
                return crun_make_error (err, errno, "cannot open directory `%s`", de->d_name);

              ret = rmdirfd (de->d_name, cfd, err);
              if (UNLIKELY (ret < 0))
                return ret;

              ret = unlinkat (dirfd (d), de->d_name, AT_REMOVEDIR);
            }
        }
    }

  return 0;
}

int
libcrun_container_delete_status (const char *state_root, const char *id, libcrun_error_t *err)
{
  int ret;
  cleanup_close int rundir_dfd = -1;
  cleanup_close int dfd = -1;
  cleanup_free char *dir = NULL;

  dir = get_run_directory (state_root);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, 0, "cannot get state directory");

  rundir_dfd = TEMP_FAILURE_RETRY (open (dir, O_DIRECTORY | O_RDONLY | O_CLOEXEC));
  if (UNLIKELY (rundir_dfd < 0))
    return crun_make_error (err, errno, "cannot open run directory `%s`", dir);

  dfd = openat (rundir_dfd, id, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dfd < 0))
    return crun_make_error (err, errno, "cannot open directory '%s/%s'", dir, id);

  ret = rmdirfd (dir, dfd, err);

  /* rmdirfd owns DFD.  */
  dfd = -1;

  if (UNLIKELY (ret < 0))
    return ret;

  ret = unlinkat (rundir_dfd, id, AT_REMOVEDIR);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot rm state directory `%s/%s`", dir, id);

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
  free (status->external_descriptors);
  free (status->created);
  free (status->scope);
}

int
libcrun_get_containers_list (libcrun_container_list_t **ret, const char *state_root, libcrun_error_t *err)
{
  struct dirent *next;
  cleanup_container_list libcrun_container_list_t *tmp = NULL;
  cleanup_free char *path = get_run_directory (state_root);
  cleanup_dir DIR *dir = NULL;

  *ret = NULL;
  dir = opendir (path);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, errno, "cannot opendir `%s`", path);

  for (next = readdir (dir); next; next = readdir (dir))
    {
      int r, exists;
      cleanup_free char *status_file = NULL;

      libcrun_container_list_t *next_container;

      if (next->d_name[0] == '.')
        continue;

      r = append_paths (&status_file, err, path, next->d_name, "status", NULL);
      if (UNLIKELY (r < 0))
        return r;

      exists = crun_path_exists (status_file, err);
      if (exists < 0)
        {
          libcrun_free_containers_list (tmp);
          return exists;
        }

      if (! exists)
        continue;

      next_container = xmalloc (sizeof (libcrun_container_list_t));
      next_container->name = xstrdup (next->d_name);
      next_container->next = tmp;
      tmp = next_container;
    }
  *ret = tmp;
  tmp = NULL;
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

/* check if the container pid is still valid.
   Returns:
   -1: on errors
    0: pid not valid
    1: pid valid and container in the running/created/paused state
*/
int
libcrun_check_pid_valid (libcrun_container_status_t *status, libcrun_error_t *err)
{
  struct pid_stat st;
  int ret;

  /* For backwards compatibility, check start time only if available. */
  if (! status->process_start_time)
    return 1;

  ret = read_pid_stat (status->pid, &st, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (status->process_start_time != st.starttime || st.state == 'Z' || st.state == 'X')
    return 0; /* stopped */

  return 1; /* running, created, or paused */
}

int
libcrun_is_container_running (libcrun_container_status_t *status, libcrun_error_t *err)
{
  int ret;

  ret = kill (status->pid, 0);
  if (UNLIKELY (ret < 0) && errno != ESRCH)
    return crun_make_error (err, errno, "kill");

  if (ret == 0)
    return libcrun_check_pid_valid (status, err);

  return 0; /* stopped */
}

int
libcrun_status_create_exec_fifo (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *state_dir = libcrun_get_state_directory (state_root, id);
  cleanup_free char *fifo_path = NULL;
  int ret, fd = -1;

  ret = append_paths (&fifo_path, err, state_dir, "exec.fifo", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

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
  cleanup_free char *fifo_path = NULL;
  char buffer[1] = {
    0,
  };
  cleanup_close int fd = -1;
  int ret;

  ret = append_paths (&fifo_path, err, state_dir, "exec.fifo", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

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
  cleanup_free char *fifo_path = NULL;
  int ret;

  ret = append_paths (&fifo_path, err, state_dir, "exec.fifo", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  return crun_path_exists (fifo_path, err);
}
