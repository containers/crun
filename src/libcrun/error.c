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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include "utils.h"

#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>

#ifdef HAVE_SYSTEMD
# include <systemd/sd-journal.h>
#endif


#define YAJL_STR(x) ((const unsigned char *) (x))

enum
  {
   LOG_FORMAT_TEXT = 0,
   LOG_FORMAT_JSON,
  };

static int log_format;

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
crun_error_write_warning_and_release (FILE *out, libcrun_error_t **err)
{
  libcrun_error_t ref;

  if (out == NULL)
    out = stderr;
  if (err == NULL || *err == NULL)
    return;

  ref = **err;
  if (ref->status)
    fprintf (out, "%s: %s\n", ref->msg, strerror (ref->status));
  else
    fprintf (out, "%s\n", ref->msg);

  free (ref->msg);
  free (ref);
  **err = NULL;
}

int
crun_error_get_errno (libcrun_error_t *err)
{
  if (err == NULL)
    return 0;
  return (*err)->status;
}

typedef char timestamp_t[64];

static void
get_timestamp (timestamp_t *timestamp, const char *suffix)
{
  struct timeval tv;
  struct tm now;

  gettimeofday (&tv, NULL);
  gmtime_r (&tv.tv_sec, &now);
  strftime ((char *) timestamp, 64, "%Y-%m-%dT%H:%M:%S", &now);
  sprintf (((char *) timestamp) + 19, ".%09ldZ%.8s", tv.tv_usec, suffix);
}

static void *
init_syslog (const char *id)
{
  openlog (id, 0, LOG_USER);
  return NULL;
}

enum
  {
   LOG_TYPE_FILE = 1,
   LOG_TYPE_SYSLOG = 2,
   LOG_TYPE_JOURNALD = 3
  };

static int
get_log_type (const char *log, const char **data)
{
  char *sep = strchr (log, ':');
  if (sep == NULL)
    {
      *data = log;
      return LOG_TYPE_FILE;
    }
  *data = sep + 1;

  if (has_prefix (log, "syslog:"))
    return LOG_TYPE_SYSLOG;
  if (has_prefix (log, "journald:"))
    return LOG_TYPE_JOURNALD;
  if (has_prefix (log, "file:"))
    return LOG_TYPE_FILE;

  return -1;
}

int
init_logging (crun_output_handler *new_output_handler, void **new_output_handler_arg,
              const char *id, const char *log, libcrun_error_t *err)
{
  if (log == NULL)
    {
      *new_output_handler = log_write_to_stderr;
      *new_output_handler_arg = NULL;
    }
  else
    {
      const char *arg = NULL;
      int log_type = get_log_type (log, &arg);

      if (log_type < 0)
        return crun_make_error (err, errno, "unknown log type %s\n", log);

      switch (log_type)
        {
        case LOG_TYPE_FILE:
          *new_output_handler = log_write_to_stream;
          *new_output_handler_arg = fopen (arg, "a+");
          if (*new_output_handler_arg == NULL)
            return crun_make_error (err, errno, "open log file %s\n", log);
          break;

        case LOG_TYPE_SYSLOG:
          *new_output_handler_arg = init_syslog (arg[0] ? arg : id);
          *new_output_handler = log_write_to_syslog;
          break;

        case LOG_TYPE_JOURNALD:
          *new_output_handler = log_write_to_syslog;
          *new_output_handler_arg = NULL;
          break;
        }
    }
  crun_set_output_handler (*new_output_handler, *new_output_handler_arg);
  return 0;
}

void
log_write_to_stream (int errno_, const char *msg, bool warning, void *arg)
{
  timestamp_t timestamp = {0, };
  FILE *stream = arg;
  int tty = isatty (fileno (stream));
  const char *color_begin = "";
  const char *color_end = "";

  if (tty)
    {
      color_begin = warning ? "\x1b[1;33m" : "\x1b[1;31m";
      color_end = "\x1b[0m";

      if (log_format == LOG_FORMAT_TEXT)
        get_timestamp (&timestamp, ": ");
    }

  if (errno_)
    fprintf (stream, "%s%s%s: %s%s\n", color_begin, timestamp, msg, strerror (errno_), color_end);
  else
    fprintf (stream, "%s%s%s%s\n", color_begin, timestamp, msg, color_end);
}

void
log_write_to_stderr (int errno_, const char *msg, bool warning, void *arg)
{
  log_write_to_stream (errno_, msg, warning, stderr);
}

void
log_write_to_syslog (int errno_, const char *msg, bool warning, void *arg)
{
  if (errno_ == 0)
    syslog (warning ? LOG_WARNING : LOG_ERR, "%s", msg);
  else
    syslog (warning ? LOG_WARNING : LOG_ERR, "%s: %s", msg, strerror (errno_));
}

void
log_write_to_journald (int errno_, const char *msg, bool warning, void *arg)
{
#ifdef HAVE_SYSTEMD
  if (errno_ == 0)
    sd_journal_send ("MESSAGE=%s", msg, "ID=%s", arg, NULL);
  else
  if (errno_ == 0)
    sd_journal_send ("MESSAGE=%s: %s", msg, strerror (errno_), "ID=%s", arg, NULL);
#endif
}

static crun_output_handler output_handler = log_write_to_stderr;
static void *output_handler_arg = NULL;
static int output_verbosity = LIBCRUN_VERBOSITY_WARNING;

void
libcrun_set_verbosity (int verbosity)
{
  output_verbosity = verbosity;
}

int
libcrun_get_verbosity ()
{
  return output_verbosity;
}

void
crun_set_output_handler (crun_output_handler handler, void *arg)
{
  output_handler = handler;
  output_handler_arg = arg;
}

static char *
make_json_error (const char *msg, int errno_, bool warning)
{
  const char *level = warning ? "warning" : "error";
  const unsigned char *buf = NULL;
  yajl_gen gen = NULL;
  char *ret = NULL;
  size_t buf_len;
  timestamp_t timestamp = {0, };

  gen = yajl_gen_alloc (NULL);
  if (gen == NULL)
    return NULL;

  get_timestamp (&timestamp, "");

  yajl_gen_map_open (gen);

  yajl_gen_string (gen, YAJL_STR ("msg"), strlen ("msg"));
  if (errno_ == 0)
    yajl_gen_string (gen, YAJL_STR (msg), strlen (msg));
  else
    {
      cleanup_free char *tmp = NULL;

      xasprintf (&tmp, "%s: %s", msg, strerror (errno_));
      yajl_gen_string (gen, YAJL_STR (tmp), strlen (tmp));
    }

  yajl_gen_string (gen, YAJL_STR ("level"), strlen ("level"));
  yajl_gen_string (gen, YAJL_STR (level), strlen (level));

  yajl_gen_string (gen, YAJL_STR ("time"), strlen ("time"));
  yajl_gen_string (gen, YAJL_STR (timestamp), strlen (timestamp));

  yajl_gen_map_close (gen);

  yajl_gen_get_buf (gen, &buf, &buf_len);
  if (buf)
    ret = strdup ((const char *) buf);

  yajl_gen_free (gen);

  return ret;
}

static void
write_log (int errno_, bool warning, const char *msg, va_list args_list)
{
  int ret;
  cleanup_free char *output = NULL;
  cleanup_free char *json = NULL;

  if (warning && output_verbosity < LIBCRUN_VERBOSITY_WARNING)
    return;

  ret = vasprintf (&output, msg, args_list);
  if (UNLIKELY (ret < 0))
    OOM ();

  switch (log_format)
    {
    case LOG_FORMAT_TEXT:
      output_handler (errno_, output, warning, output_handler_arg);
      break;

    case LOG_FORMAT_JSON:
      json = make_json_error (output, errno_, warning);
      if (json)
        output_handler (0, json, warning, output_handler_arg);
      else
        output_handler (errno_, output, warning, output_handler_arg);
      break;
    }
}

void
libcrun_warning (const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);
  write_log (0, true, msg, args_list);
  va_end (args_list);
}

void
libcrun_error (int errno_, bool also_stderr, const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);

  write_log (errno_, false, msg, args_list);
  va_end (args_list);
  exit (EXIT_FAILURE);
}

void __attribute__ ((noreturn))
libcrun_fail_with_error (int errno_, const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);
  write_log (errno_, false, msg, args_list);
  va_end (args_list);
  exit (EXIT_FAILURE);
}

int
crun_set_log_format (const char *format, libcrun_error_t *err)
{
  if (strcmp (format, "text") == 0)
    log_format = LOG_FORMAT_TEXT;
  else if (strcmp (format, "json") == 0)
    log_format = LOG_FORMAT_JSON;
  else
    return crun_make_error (err, 0, "unknown log format type %s", format);

  return 0;
}
