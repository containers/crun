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
#include "error.h"
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
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
