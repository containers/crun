/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#ifndef ERROR_H
# define ERROR_H
# include <config.h>
# ifdef HAVE_ERROR_H
#  include <error.h>
# else
#  define error(status, errno, fmt, ...) do {                           \
    if (errno == 0)                                                     \
      fprintf (stderr, "crun: " fmt "\n", ##__VA_ARGS__);               \
    else                                                                \
      {                                                                 \
        fprintf (stderr, "crun: " fmt, ##__VA_ARGS__);                  \
        fprintf (stderr, ": %s\n", strerror (errno));                   \
      }                                                                 \
    if (status)                                                         \
      exit (status);                                                    \
  } while(0)
# endif
# include <stdlib.h>
# include <stdio.h>
# include <stdbool.h>

struct libcrun_error_s
{
  int status;
  char *msg;
};
typedef struct libcrun_error_s *libcrun_error_t;

void oom_handler ();

typedef void (*crun_output_handler) (int errno_, const char *msg, bool warning, void *arg);

void crun_set_output_handler (crun_output_handler handler, void *arg);

void log_write_to_stream (int errno_, const char *msg, bool warning, void *arg);

void log_write_to_stderr (int errno_, const char *msg, bool warning, void *arg);

# define OOM() do {oom_handler ();} while (0)

int crun_make_error (libcrun_error_t *err, int status, const char *msg, ...);

int crun_error_get_errno (libcrun_error_t *err);

int crun_error_release (libcrun_error_t *err);

void crun_error_write_warning_and_release (FILE *out, libcrun_error_t **err);

void libcrun_warning (const char *msg, ...);

void libcrun_fail_with_error (int errno_, const char *msg, ...) __attribute__ ((noreturn));

enum
  {
    LIBCRUN_VERBOSITY_ERROR,
    LIBCRUN_VERBOSITY_WARNING,
  };

void libcrun_set_verbosity (int verbosity);
int libcrun_get_verbosity ();

#endif
