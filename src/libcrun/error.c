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
#  include <systemd/sd-journal.h>
#endif

#define YAJL_STR(x) ((const unsigned char *) (x))

enum
{
  LOG_FORMAT_TEXT = 0,
  LOG_FORMAT_JSON,
};

static int log_format;
static int output_verbosity = LIBCRUN_VERBOSITY_ERROR;

int
libcrun_make_error (libcrun_error_t *err, int status, const char *msg, ...)
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
crun_error_wrap (libcrun_error_t *err, const char *fmt, ...)
{
  cleanup_free char *msg = NULL;
  cleanup_free char *tmp = NULL;
  va_list args_list;
  char *swap;
  int ret;

  if (err == NULL || *err == NULL)
    {
      // Internal error
      return 0;
    }

  ret = -(*err)->status - 1;

  va_start (args_list, fmt);

  if (vasprintf (&msg, fmt, args_list) < 0)
    {
      va_end (args_list);
      msg = NULL;
      return ret;
    }
  va_end (args_list);

  xasprintf (&tmp, "%s: %s", msg, (*err)->msg);
  swap = tmp;
  tmp = (*err)->msg;
  (*err)->msg = swap;

  return ret;
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

int
libcrun_error_release (libcrun_error_t *err)
{
  return crun_error_release (err);
}

void
crun_error_write_warning_and_release (FILE *out, libcrun_error_t **err)
{
  libcrun_error_t ref;

  if (out == NULL)
    out = stderr;
  if (err == NULL || *err == NULL || **err == NULL)
    {
      // Internal error
      return;
    }

  ref = **err;
  if (ref->status)
    fprintf (out, "%s: %s\n", ref->msg, strerror (ref->status));
  else
    fprintf (out, "%s\n", ref->msg);

  free (ref->msg);
  free (ref);
  **err = NULL;
}

void
libcrun_error_write_warning_and_release (FILE *out, libcrun_error_t **err)
{
  return crun_error_write_warning_and_release (out, err);
}

int
crun_error_get_errno (libcrun_error_t *err)
{
  if (err == NULL || *err == NULL)
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
  sprintf (((char *) timestamp) + 19, ".%06lldZ%.8s", (long long int) tv.tv_usec, suffix);
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
libcrun_init_logging (crun_output_handler *new_output_handler, void **new_output_handler_arg, const char *id,
                      const char *log, libcrun_error_t *err)
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
        return crun_make_error (err, errno, "unknown log type `%s`", log);

      switch (log_type)
        {
        case LOG_TYPE_FILE:
          *new_output_handler = log_write_to_stream;
          *new_output_handler_arg = fopen (arg, "a+e");
          if (*new_output_handler_arg == NULL)
            return crun_make_error (err, errno, "open log file `%s`", log);
          if (output_verbosity >= LIBCRUN_VERBOSITY_WARNING)
            setlinebuf (*new_output_handler_arg);
          break;

        case LOG_TYPE_SYSLOG:
          *new_output_handler_arg = init_syslog (arg[0] ? arg : id);
          *new_output_handler = log_write_to_syslog;
          break;

        case LOG_TYPE_JOURNALD:
          *new_output_handler = log_write_to_journald;
          *new_output_handler_arg = (void *) id;
          break;
        }
    }
  crun_set_output_handler (*new_output_handler, *new_output_handler_arg);
  return 0;
}

void
log_write_to_stream (int errno_, const char *msg, int verbosity, void *arg)
{
  timestamp_t timestamp = {
    0,
  };
  FILE *stream = arg;
  int tty = isatty (fileno (stream));
  const char *color_begin = "";
  const char *color_end = "";

  if (tty)
    {
      switch (verbosity)
        {
        case LIBCRUN_VERBOSITY_DEBUG:
          color_begin = "\x1b[1;34m";
          color_end = "\x1b[0m";
          break;
        case LIBCRUN_VERBOSITY_WARNING:
          color_begin = "\x1b[1;33m";
          color_end = "\x1b[0m";
          break;
        case LIBCRUN_VERBOSITY_ERROR:
          color_begin = "\x1b[1;31m";
          color_end = "\x1b[0m";
          break;
        }

      if (log_format == LOG_FORMAT_TEXT)
        get_timestamp (&timestamp, ": ");
    }

  if (errno_)
    fprintf (stream, "%s%s%s: %s%s\n", color_begin, timestamp, msg, strerror (errno_), color_end);
  else
    fprintf (stream, "%s%s%s%s\n", color_begin, timestamp, msg, color_end);
}

void
log_write_to_stderr (int errno_, const char *msg, int verbosity, void *arg arg_unused)
{
  log_write_to_stream (errno_, msg, verbosity, stderr);
}

void
log_write_to_syslog (int errno_, const char *msg, int verbosity, void *arg arg_unused)
{
  int priority = LOG_ERR;
  switch (verbosity)
    {
    case LIBCRUN_VERBOSITY_DEBUG:
      priority = LOG_DEBUG;
      break;
    case LIBCRUN_VERBOSITY_WARNING:
      priority = LOG_WARNING;
      break;
    case LIBCRUN_VERBOSITY_ERROR:
      priority = LOG_ERR;
      break;
    }
  if (errno_ == 0)
    syslog (priority, "%s", msg);
  else
    syslog (priority, "%s: %s", msg, strerror (errno_));
}

void
log_write_to_journald (int errno_, const char *msg, int verbosity, void *arg arg_unused)
{
  (void) errno_;
  (void) msg;
  (void) verbosity;
#ifdef HAVE_SYSTEMD
  int priority = LOG_ERR;
  switch (verbosity)
    {
    case LIBCRUN_VERBOSITY_DEBUG:
      priority = LOG_DEBUG;
      break;
    case LIBCRUN_VERBOSITY_WARNING:
      priority = LOG_WARNING;
      break;
    case LIBCRUN_VERBOSITY_ERROR:
      priority = LOG_ERR;
      break;
    }
  if (errno_ == 0)
    sd_journal_send ("PRIORITY=%d", priority, "MESSAGE=%s", msg, "ID=%s", arg, NULL);
  else
    sd_journal_send ("PRIORITY=%d", priority, "MESSAGE=%s: %s", msg, strerror (errno_), "ID=%s",
                     arg, NULL);
#endif
}

static crun_output_handler output_handler = log_write_to_stderr;
static void *output_handler_arg = NULL;

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
make_json_error (const char *msg, int errno_, int verbosity)
{
  const char *level;
  switch (verbosity)
    {
    case LIBCRUN_VERBOSITY_DEBUG:
      level = "debug";
      break;
    case LIBCRUN_VERBOSITY_WARNING:
      level = "warning";
      break;
    case LIBCRUN_VERBOSITY_ERROR:
      level = "error";
      break;
    }
  const unsigned char *buf = NULL;
  yajl_gen gen = NULL;
  char *ret = NULL;
  size_t buf_len;
  timestamp_t timestamp = {
    0,
  };

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
write_log (int errno_, int verbosity, const char *msg, va_list args_list)
{
  int ret;
  cleanup_free char *output = NULL;
  cleanup_free char *json = NULL;

  if (verbosity > output_verbosity)
    return;

  ret = vasprintf (&output, msg, args_list);
  if (UNLIKELY (ret < 0))
    OOM ();

  if (verbosity == LIBCRUN_VERBOSITY_ERROR && output_handler != log_write_to_stderr)
    log_write_to_stderr (errno_, output, LIBCRUN_VERBOSITY_ERROR, NULL);

  switch (log_format)
    {
    case LOG_FORMAT_TEXT:
      output_handler (errno_, output, verbosity, output_handler_arg);
      break;

    case LOG_FORMAT_JSON:
      json = make_json_error (output, errno_, verbosity);
      if (json)
        output_handler (0, json, verbosity, output_handler_arg);
      else
        output_handler (errno_, output, verbosity, output_handler_arg);
      break;
    }
}

void
libcrun_debug (const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);
  write_log (0, LIBCRUN_VERBOSITY_DEBUG, msg, args_list);
  va_end (args_list);
}

void
libcrun_warning (const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);
  write_log (0, LIBCRUN_VERBOSITY_WARNING, msg, args_list);
  va_end (args_list);
}

void
libcrun_error (int errno_, const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);

  write_log (errno_, LIBCRUN_VERBOSITY_ERROR, msg, args_list);
  va_end (args_list);
}

void __attribute__ ((noreturn))
libcrun_fail_with_error (int errno_, const char *msg, ...)
{
  va_list args_list;
  va_start (args_list, msg);
  write_log (errno_, LIBCRUN_VERBOSITY_ERROR, msg, args_list);
  va_end (args_list);
  exit (EXIT_FAILURE);
}

int
libcrun_set_log_format (const char *format, libcrun_error_t *err)
{
  if (strcmp (format, "text") == 0)
    log_format = LOG_FORMAT_TEXT;
  else if (strcmp (format, "json") == 0)
    log_format = LOG_FORMAT_JSON;
  else
    return crun_make_error (err, 0, "unknown log format type `%s`", format);

  return 0;
}

int
yajl_error_to_crun_error (int yajl_status, libcrun_error_t *err)
{
  switch (yajl_status)
    {
    case yajl_gen_status_ok:
      return 0;

    case yajl_gen_keys_must_be_strings:
      return crun_make_error (err, 0, "generate JSON document: gen keys must be strings");

    case yajl_max_depth_exceeded:
      return crun_make_error (err, 0, "generate JSON document: max depth exceeded");

    case yajl_gen_in_error_state:
      return crun_make_error (err, 0, "generate JSON document: complete JSON document generated");

    case yajl_gen_generation_complete:
      return crun_make_error (err, 0, "generate JSON document: called while in error state");

    case yajl_gen_invalid_number:
      return crun_make_error (err, 0, "generate JSON document: invalid number");

    case yajl_gen_no_buf:
      return crun_make_error (err, 0, "generate JSON document: no buffer provided");

    case yajl_gen_invalid_string:
      return crun_make_error (err, 0, "generate JSON document: invalid string");

    default:
      return crun_make_error (err, 0, "generate JSON document");
    }
}
