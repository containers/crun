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
#include "utils.h"
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_SELINUX
# include <selinux/selinux.h>
#endif

void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

void
cleanup_closep (void *p)
{
  int *pp = p;
  if (*pp >= 0)
    close (*pp);
}

void *
xmalloc (size_t size)
{
  void *res = malloc (size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

void *
xrealloc (void *ptr, size_t size)
{
  void *res = realloc (ptr, size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}


char *
argp_mandatory_argument (char *arg, struct argp_state *state)
{
  if (arg)
    return arg;
  return state->argv[state->next++];
}

int
crun_path_exists (const char *path, int readonly, libcrun_error_t *err)
{
  int ret = access (path, readonly ? R_OK : W_OK);
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "accessing file '%s'", path);
  return !ret;
}

int
xasprintf (char **str, const char *fmt, ...)
{
  int ret;
  va_list args_list;

  va_start (args_list, fmt);

  ret = vasprintf (str, fmt, args_list);
  if (UNLIKELY (ret < 0))
    OOM ();

  va_end (args_list);
  return ret;
}

char *
xstrdup (const char *str)
{
  char *ret;
  if (str == NULL)
    return NULL;

  ret = strdup (str);
  if (ret == NULL)
    OOM ();

  return ret;
}

int
write_file_at (int dirfd, const char *name, const void *data, size_t len, libcrun_error_t *err)
{
  cleanup_close int fd = openat (dirfd, name, O_WRONLY);
  int ret;
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  ret = write (fd, data, len);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  return ret;
}

int
write_file (const char *name, const void *data, size_t len, libcrun_error_t *err)
{
  cleanup_close int fd = open (name, O_WRONLY);
  int ret;
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  ret = write (fd, data, len);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  return ret;
}

static int
ensure_directory_internal (char *path, size_t len, int mode, libcrun_error_t *err)
{
  char *it = path + len;
  int ret;
  ret = crun_path_exists (path, 1, err);
  if (ret > 0)
    return 0;

  while (it > path && *it != '/')
    {
      it--;
      len--;
    }
  if (it == path)
    return 0;

  *it = '\0';

  ret = ensure_directory_internal (path, len - 1, mode, err);
  if (UNLIKELY (ret < 0))
    return ret;
  *it = '/';

  ret = mkdir (path, mode);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "creating file '%s'", path);
  return 0;
}

int
crun_ensure_directory (const char *path, int mode, libcrun_error_t *err)
{
  cleanup_free char *tmp = xstrdup (path);
  return ensure_directory_internal (tmp, strlen (tmp), mode, err);
}

int
detach_process ()
{
  pid_t pid;
  if (setsid () < 0)
    return -1;
  pid = fork ();
  if (pid < 0)
    return -1;
  if (pid != 0)
    _exit (EXIT_SUCCESS);
  return 0;
}

int
create_file_if_missing_at (int dirfd, const char *file, libcrun_error_t *err)
{
  int ret = faccessat (dirfd, file, R_OK, 0);
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "accessing file '%s'", file);

  if (ret)
    {
      cleanup_close int fd_write = openat (dirfd, file, O_CREAT | O_WRONLY, 0700);
      if (fd_write < 0)
        return crun_make_error (err, errno, "creating file '%s'", file);
    }
  return 0;
}

int
check_running_in_user_namespace (libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  size_t len;
  int ret = read_all_file ("/proc/self/uid_map", &buffer, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;
  return strstr (buffer, "4294967295") ? 1 : 0;
}

int
add_selinux_mount_label (char **ret, const char *data, const char *label, libcrun_error_t *err)
{
#ifdef HAVE_SELINUX
  if (label && is_selinux_enabled () > 0)
    {
      if (data && *data)
        xasprintf (ret, "%s,context=\"%s\"", data, label);
      else
        xasprintf (ret, "context=\"%s\"", label);
      return 0;
    }
#endif
  *ret = xstrdup (data);
  return 0;

}

int
set_selinux_exec_label (const char *label, libcrun_error_t *err)
{
#ifdef HAVE_SELINUX
  if (is_selinux_enabled () > 0)
    if (UNLIKELY (setexeccon (label) < 0))
      {
        crun_make_error (err, 0, "error setting SELinux exec label");
        return -1;
      }
#endif
  return 0;
}

int
read_all_file (const char *path, char **out, size_t *len, libcrun_error_t *err)
{
  cleanup_close int fd;
  int ret;
  cleanup_free char *buf = NULL;
  struct stat stat;
  size_t nread, allocated;

  do
    fd = open (path, O_RDONLY);
  while (fd < 0 && errno == EINTR);

  if (UNLIKELY (fd < 0))
    return crun_make_error (err, 0, "error opening file '%s'", path);

  ret = fstat (fd, &stat);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "error stat'ing file '%s'", path);

  /* NUL terminate the buffer.  */
  allocated = stat.st_size;
  if (stat.st_size)
    allocated = 256;
  buf = xmalloc (allocated + 1);
  buf[stat.st_size] = '\0';
  nread = 0;
  while ((stat.st_size && nread < stat.st_size) || 1)
    {
      do
        ret = read (fd, buf + nread, allocated - nread);
      while (ret < 0 && errno == EINTR);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "error reading from file '%s'", path);

      nread += ret;

      if (nread < allocated)
        break;

      allocated += 256;
      buf = xrealloc (buf, allocated + 1);
      buf[allocated] = '\0';
    }
  *out = buf;
  buf = NULL;
  if (len)
    *len = nread;
  return 0;
}
