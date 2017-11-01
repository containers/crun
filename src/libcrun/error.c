/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
 * libocispec is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libocispec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <config.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include "utils.h"

int
crun_make_error (libcrun_error_t *err, int status, const char *msg, ...)
{
  va_list args_list;
  libcrun_error_t ptr;
  va_start (args_list, msg);
  *err = xmalloc (sizeof (struct libcrun_error_s));
  ptr = *err;
  ptr->status = status;
  if (vasprintf (&(ptr->msg), msg, args_list) < 0)
    OOM ();

  va_end (args_list);
  return -status - 1;
}

int
crun_error_release (libcrun_error_t *err)
{
  libcrun_error_t ptr;
  if (err == NULL)
    return 0;

  ptr = *err;
  if (ptr == NULL)
    return 0;

  free (ptr->msg);
  free (ptr);
  *err = NULL;
  return 0;
}

void
oom_handler ()
{
  fprintf (stderr, "out of memory");
  exit (EXIT_FAILURE);
}

void
crun_error_write_warning_and_release (FILE *out, libcrun_error_t *err)
{
  libcrun_error_t ref;

  if (out == NULL)
    out = stderr;
  if (err == NULL)
    return;

  ref = *err;
  if (ref->status)
    fprintf (out, "%s: %s\n", ref->msg, strerror (ref->status));
  else
    fprintf (out, "%s\n", ref->msg);
  crun_error_release (err);
}

int
crun_error_get_errno (libcrun_error_t *err)
{
  if (err == NULL)
    return 0;
  return (*err)->status;
}

static void
write_log (FILE *out, int errno_, int color, const char *msg, va_list args_list)
{
  int ret;
  cleanup_free char *warning = NULL;
  struct timeval tv;
  struct tm now;
  char timestamp[64];
  int can_color = isatty (fileno (out));
  char color_begin[32];
  const char *color_end = can_color ? "\x1b[0m" : "";

  if (can_color)
    sprintf (color_begin, "\x1b[1;%dm", color);
  else
    color_begin[0] = '\0';

  gettimeofday (&tv, NULL);
  gmtime_r (&tv.tv_sec, &now);
  strftime (timestamp, sizeof (timestamp), "%Y-%m-%dT%H:%M:%S", &now);

  ret = vasprintf (&warning, msg, args_list);
  if (UNLIKELY (ret < 0))
    OOM ();

  if (errno_)
    fprintf (out, "%s%s.%09ldZ: %s: %s%s\n", color_begin, timestamp, tv.tv_usec, strerror (errno_), warning, color_end);
  else
    fprintf (out, "%s%s.%09ldZ: %s%s\n", color_begin, timestamp, tv.tv_usec, warning, color_end);
}

void
libcrun_warning (FILE *out, const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);
  write_log (out ? out : stderr, 0, 33, msg, args_list);
  va_end (args_list);
}

void __attribute__ ((noreturn))
libcrun_fail_with_error (int errno_, const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);
  write_log (stderr, errno_, 31, msg, args_list);
  va_end (args_list);
  exit (EXIT_FAILURE);
}
