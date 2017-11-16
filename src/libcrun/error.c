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

void
log_write_to_stderr (int errno_, const char *msg, bool warning, void *arg)
{
  struct timeval tv;
  struct tm now;
  char timestamp[64];
  int can_color = isatty (2);
  const char *color_begin = "";
  const char *color_end = can_color ? "\x1b[0m" : "";

  if (can_color)
    color_begin = warning ? "\x1b[1;33m" : "\x1b[1;31m";

  gettimeofday (&tv, NULL);
  gmtime_r (&tv.tv_sec, &now);
  strftime (timestamp, sizeof (timestamp), "%Y-%m-%dT%H:%M:%S", &now);

  if (errno_)
    fprintf (stderr, "%s%s.%09ldZ: %s: %s%s\n", color_begin, timestamp, tv.tv_usec, msg, strerror (errno_), color_end);
  else
    fprintf (stderr, "%s%s.%09ldZ: %s%s\n", color_begin, timestamp, tv.tv_usec, msg, color_end);
}

static crun_output_handler output_handler = log_write_to_stderr;
static void *output_handler_arg = NULL;

void
crun_set_output_handler (crun_output_handler handler, void *arg)
{
  output_handler = handler;
  output_handler_arg = arg;
}

static void
write_log (FILE *out, int errno_, bool warning, const char *msg, va_list args_list)
{
  int ret;
  cleanup_free char *output = NULL;

  ret = vasprintf (&output, msg, args_list);
  if (UNLIKELY (ret < 0))
    OOM ();

  output_handler (errno_, output, warning, output_handler_arg);
}

void
libcrun_warning (const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);
  write_log (stderr, 0, true, msg, args_list);
  va_end (args_list);
}

void __attribute__ ((noreturn))
libcrun_fail_with_error (int errno_, const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);
  write_log (stderr, errno_, false, msg, args_list);
  va_end (args_list);
  exit (EXIT_FAILURE);
}
