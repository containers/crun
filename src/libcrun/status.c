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
#include <yyjson.h>
#include <ocispec/json_common.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>

#define STEAL_POINTER(x, y) \
  do                        \
    {                       \
      *x = y;               \
      y = NULL;             \
  } while (0)

struct pid_stat
{
  char state;
  unsigned long long starttime;
};

/* If ID is not NULL, then ennsure that it does not contain any slash.  */
static int
validate_id (const char *id, libcrun_error_t *err)
{
  if (id && strchr (id, '/') != NULL)
    return crun_make_error (err, 0, "invalid character `/` in the ID `%s`", id);

  return 0;
}

int
get_run_directory (char **out, const char *state_root, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *root = NULL;

  if (state_root)
    root = xstrdup (state_root);
  if (root == NULL)
    {
      const char *runtime_dir = getenv ("XDG_RUNTIME_DIR");
      if (runtime_dir && runtime_dir[0] != '\0')
        {
          ret = append_paths (&root, err, runtime_dir, "crun", NULL);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  if (root == NULL)
    root = xstrdup ("/run/crun");

  ret = crun_ensure_directory (root, 0700, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  STEAL_POINTER (out, root);

  return 0;
}

int
get_shared_empty_directory_path (char **out, const char *state_root, libcrun_error_t *err)
{
  cleanup_free char *run_dir = NULL;
  int ret;

  ret = get_run_directory (&run_dir, state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (out, err, run_dir, ".empty-directory", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Ensure the empty directory exists */
  ret = crun_ensure_directory (*out, 0555, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

int
libcrun_get_state_directory (char **out, const char *state_root, const char *id, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *path = NULL;
  cleanup_free char *root = NULL;

  ret = validate_id (id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = get_run_directory (&root, state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (&path, err, root, id, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  STEAL_POINTER (out, path);

  return 0;
}

static int
get_state_directory_status_file (char **out, const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *root = NULL;
  cleanup_free char *path = NULL;
  int ret;

  ret = validate_id (id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = get_run_directory (&root, state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (&path, err, root, id, "status", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  STEAL_POINTER (out, path);

  return 0;
}

static int
read_pid_stat (pid_t pid, struct pid_stat *st, libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  cleanup_close int fd = -1;
  char pid_stat_file[64];
  char *it, *s;
  int i, ret;

  ret = snprintf (pid_stat_file, sizeof (pid_stat_file), "/proc/%d/stat", pid);
  if (UNLIKELY (ret >= (int) sizeof (pid_stat_file)))
    return crun_make_error (err, 0, "internal error: static buffer too small");

  fd = open (pid_stat_file, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    {
      /* The process already exited.  */
      if (errno == ENOENT || errno == ESRCH)
        {
          memset (st, 0, sizeof (*st));
          return 0;
        }
      return crun_make_error (err, errno, "open state file `%s`", pid_stat_file);
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
  cleanup_free char *file_tmp = NULL;
  cleanup_free char *file = NULL;
  size_t len;
  cleanup_close int fd_write = -1;
  const char *buf = NULL;
  struct pid_stat st;
  const char *tmp;
  json_gen_ctx *gen = NULL;

  ret = get_state_directory_status_file (&file, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = read_pid_stat (status->pid, &st, err);
  if (UNLIKELY (ret < 0))
    return ret;

  status->process_start_time = st.starttime;

  xasprintf (&file_tmp, "%s.tmp", file);
  fd_write = open (file_tmp, O_CREAT | O_WRONLY | O_CLOEXEC, 0700);
  if (UNLIKELY (fd_write < 0))
    return crun_make_error (err, errno, "cannot open status file");

  if (! json_gen_init (&gen, NULL))
    return crun_make_error (err, 0, "json_gen_init failed");

  json_gen_config (gen, json_gen_beautify, 1);

  r = json_gen_map_open (gen);
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, "pid", strlen ("pid"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = map_int (gen, status->pid);
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, "process-start-time", strlen ("process-start-time"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = map_int (gen, status->process_start_time);
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, "cgroup-path", strlen ("cgroup-path"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  tmp = status->cgroup_path ? status->cgroup_path : "";
  r = json_gen_string (gen, tmp, strlen (tmp));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, "scope", strlen ("scope"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  tmp = status->scope ? status->scope : "";
  r = json_gen_string (gen, tmp, strlen (tmp));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, "rootfs", strlen ("rootfs"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, status->rootfs, strlen (status->rootfs));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, "systemd-cgroup", strlen ("systemd-cgroup"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_bool (gen, status->systemd_cgroup);
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, "bundle", strlen ("bundle"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, status->bundle, strlen (status->bundle));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, "created", strlen ("created"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, status->created, strlen (status->created));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  if (status->owner)
    {
      r = json_gen_string (gen, "owner", strlen ("owner"));
      if (UNLIKELY (r != json_gen_status_ok))
        goto gen_error;

      r = json_gen_string (gen, status->owner, strlen (status->owner));
      if (UNLIKELY (r != json_gen_status_ok))
        goto gen_error;
    }

  r = json_gen_string (gen, "detached", strlen ("detached"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_bool (gen, status->detached);
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, "external_descriptors", strlen ("external_descriptors"));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_string (gen, status->external_descriptors, strlen (status->external_descriptors));
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_map_close (gen);
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  r = json_gen_get_buf (gen, &buf, &len);
  if (UNLIKELY (r != json_gen_status_ok))
    goto gen_error;

  ret = safe_write (fd_write, "status file", buf, len, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  close_and_reset (&fd_write);

  if (UNLIKELY (rename (file_tmp, file) < 0))
    {
      ret = crun_make_error (err, errno, "cannot rename status file");
      goto exit;
    }

exit:
  if (gen)
    json_gen_free (gen);

  return ret;

gen_error:
  if (gen)
    json_gen_free (gen);

  return json_gen_error_to_crun_error (r, err);
}

int
libcrun_read_container_status (libcrun_container_status_t *status, const char *state_root, const char *id,
                               libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  int ret;
  cleanup_free char *file = NULL;
  yyjson_doc *doc = NULL;
  yyjson_val *tree, *tmp;
  const char *val;

  ret = get_state_directory_status_file (&file, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = read_all_file (file, &buffer, NULL, err);
  if (UNLIKELY (ret < 0))
    {

      if (crun_error_get_errno (err) == ENOENT)
        {
          cleanup_free char *statedir = NULL;
          libcrun_error_t tmp_err;
          int tmp_ret;

          tmp_ret = libcrun_get_state_directory (&statedir, state_root, id, &tmp_err);
          if (UNLIKELY (tmp_ret < 0))
            crun_error_release (&tmp_err);
          else
            {
              tmp_ret = crun_path_exists (statedir, &tmp_err);
              if (UNLIKELY (tmp_ret < 0))
                crun_error_release (&tmp_err);
              else if (tmp_ret == 0)
                return crun_error_wrap (err, "container `%s` does not exist", id);
            }
        }
      return ret;
    }

  doc = yyjson_read (buffer, strlen (buffer), 0);
  if (UNLIKELY (doc == NULL))
    return crun_make_error (err, 0, "cannot parse status file");
  tree = yyjson_doc_get_root (doc);

  {
    tmp = yyjson_obj_get (tree, "pid");
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "`pid` missing in `%s`", file);
    status->pid = (pid_t) yyjson_get_int (tmp);
  }
  {
    tmp = yyjson_obj_get (tree, "process-start-time");
    if (UNLIKELY (tmp == NULL))
      status->process_start_time = 0; /* backwards compatibility */
    else
      status->process_start_time = yyjson_get_uint (tmp);
  }
  {
    tmp = yyjson_obj_get (tree, "cgroup-path");
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "`cgroup-path` missing in `%s`", file);
    val = yyjson_get_str (tmp);
    if (UNLIKELY (val == NULL))
      return crun_make_error (err, 0, "`cgroup-path` is not a string in `%s`", file);
    status->cgroup_path = xstrdup (val);
  }
  {
    tmp = yyjson_obj_get (tree, "scope");
    status->scope = tmp ? xstrdup (yyjson_get_str (tmp)) : NULL;
  }
  {
    tmp = yyjson_obj_get (tree, "rootfs");
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "`rootfs` missing in `%s`", file);
    val = yyjson_get_str (tmp);
    if (UNLIKELY (val == NULL))
      return crun_make_error (err, 0, "`rootfs` is not a string in `%s`", file);
    status->rootfs = xstrdup (val);
  }
  {
    status->systemd_cgroup = yyjson_is_true (yyjson_obj_get (tree, "systemd-cgroup"));
  }
  {
    tmp = yyjson_obj_get (tree, "bundle");
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "`bundle` missing in `%s`", file);
    val = yyjson_get_str (tmp);
    if (UNLIKELY (val == NULL))
      return crun_make_error (err, 0, "`bundle` is not a string in `%s`", file);
    status->bundle = xstrdup (val);
  }
  {
    tmp = yyjson_obj_get (tree, "created");
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "`created` missing in `%s`", file);
    val = yyjson_get_str (tmp);
    if (UNLIKELY (val == NULL))
      return crun_make_error (err, 0, "`created` is not a string in `%s`", file);
    status->created = xstrdup (val);
  }
  {
    tmp = yyjson_obj_get (tree, "owner");
    status->owner = tmp ? xstrdup (yyjson_get_str (tmp)) : NULL;
  }
  {
    status->detached = yyjson_is_true (yyjson_obj_get (tree, "detached"));
  }
  {
    tmp = yyjson_obj_get (tree, "external_descriptors");
    status->external_descriptors = tmp ? xstrdup (yyjson_get_str (tmp)) : NULL;
  }
  yyjson_doc_free (doc);
  return 0;
}

int
libcrun_status_check_directories (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *dir = NULL;
  int ret;

  ret = libcrun_get_state_directory (&dir, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

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
  __attribute__ ((unused)) cleanup_close int fd_cleanup = fd;

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
        retry_unlink:
          ret = unlinkat (dirfd (d), de->d_name, AT_REMOVEDIR);
          if (ret < 0 && errno == EBUSY)
            {
              cleanup_close int tfd = openat (dirfd (d), de->d_name, O_CLOEXEC | O_PATH | O_NOFOLLOW);
              if (tfd >= 0)
                {
                  proc_fd_path_t procpath;

                  get_proc_self_fd_path (procpath, tfd);
                  if (umount2 (procpath, MNT_DETACH) == 0)
                    goto retry_unlink;
                }
            }
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

  ret = validate_id (id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = get_run_directory (&dir, state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  rundir_dfd = TEMP_FAILURE_RETRY (open (dir, O_DIRECTORY | O_PATH | O_CLOEXEC));
  if (UNLIKELY (rundir_dfd < 0))
    return crun_make_error (err, errno, "cannot open run directory `%s`", dir);

  dfd = openat (rundir_dfd, id, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  if (UNLIKELY (dfd < 0))
    return crun_make_error (err, errno, "cannot open directory `%s/%s`", dir, id);

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
  free (status->owner);
}

int
libcrun_get_containers_list (libcrun_container_list_t **out, const char *state_root, libcrun_error_t *err)
{
  struct dirent *next;
  cleanup_container_list libcrun_container_list_t *tmp = NULL;
  cleanup_free char *root = NULL;
  cleanup_dir DIR *dir = NULL;
  int ret;

  *out = NULL;

  ret = get_run_directory (&root, state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  dir = opendir (root);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, errno, "cannot opendir `%s`", root);

  for (next = readdir (dir); next; next = readdir (dir))
    {
      int exists;
      cleanup_free char *status_file = NULL;

      libcrun_container_list_t *next_container;

      if (next->d_name[0] == '.')
        continue;

      ret = append_paths (&status_file, err, root, next->d_name, "status", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      exists = crun_path_exists (status_file, err);
      if (exists < 0)
        {
          return exists;
        }

      if (! exists)
        {
          libcrun_error (errno, "error opening file `%s`", status_file);
          continue;
        }

      next_container = xmalloc (sizeof (libcrun_container_list_t));
      next_container->name = xstrdup (next->d_name);
      next_container->next = tmp;
      tmp = next_container;
    }

  STEAL_POINTER (out, tmp);

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
  cleanup_free char *state_dir = NULL;
  cleanup_free char *fifo_path = NULL;
  int ret, fd = -1;

  ret = libcrun_get_state_directory (&state_dir, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (&fifo_path, err, state_dir, "exec.fifo", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  libcrun_debug ("Creating exec fifo: %s", fifo_path);
  ret = mkfifo (fifo_path, 0600);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mkfifo");

  fd = open (fifo_path, O_NONBLOCK | O_CLOEXEC);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "cannot open pipe `%s`", fifo_path);

  return fd;
}

int
libcrun_status_write_exec_fifo (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *state_dir = NULL;
  cleanup_free char *fifo_path = NULL;
  char buffer[1] = {
    0,
  };
  cleanup_close int fd = -1;
  int ret;

  ret = libcrun_get_state_directory (&state_dir, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (&fifo_path, err, state_dir, "exec.fifo", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  fd = open (fifo_path, O_WRONLY | O_CLOEXEC);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "cannot open `%s`", fifo_path);

  ret = unlink (fifo_path);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "unlink `%s`", fifo_path);

  ret = TEMP_FAILURE_RETRY (write (fd, buffer, 1));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write to exec.fifo");

  return 0;
}

int
libcrun_status_has_read_exec_fifo (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *state_dir = NULL;
  cleanup_free char *fifo_path = NULL;
  int ret;

  ret = libcrun_get_state_directory (&state_dir, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (&fifo_path, err, state_dir, "exec.fifo", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  return crun_path_exists (fifo_path, err);
}
