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

char *
argp_mandatory_argument (char *arg, struct argp_state *state)
{
  if (arg)
    return arg;
  return state->argv[state->next++];
}

int
crun_static_error (char **err, int status, const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);

  if (vasprintf (err, msg, args_list) < 0)
    OOM ();

  va_end (args_list);
  return -status - 1;
}

int
crun_path_exists (const char *path, int readonly, char **err)
{
  int ret = access (path, readonly ? R_OK : W_OK);
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_static_error (err, errno, "accessing file '%s'", path);
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
write_file (const char *name, const void *data, size_t len, char **err)
{
  cleanup_close int fd = open (name, O_WRONLY);
  int ret;
  if (UNLIKELY (fd < 0))
    return crun_static_error (err, errno, "writing file '%s'", name);

  ret = write (fd, data, len);
  if (UNLIKELY (ret < 0))
    return crun_static_error (err, errno, "writing file '%s'", name);

  return ret;
}

static int
ensure_directory_internal (char *path, size_t len, int mode, char **err)
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
    return crun_static_error (err, errno, "creating file '%s'", path);
  return 0;
}

int
crun_ensure_directory (const char *path, int mode, char **err)
{
  cleanup_free char *tmp = xstrdup (path);
  return ensure_directory_internal (tmp, strlen (tmp), mode, err);
}
