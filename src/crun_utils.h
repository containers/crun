/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef CRUN_UTILS_H
#define CRUN_UTILS_H

/* Self-contained helpers for the crun binary so that it does not have to
   include the internal libcrun/utils.h (which pulls in the internal,
   non-public headers).  The binary is a pure consumer of the public
   <libcrun.h> API; everything here is either libc or a trivial inline.  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __GNUC__
#  define LIKELY(x) __builtin_expect ((x), 1)
#  define UNLIKELY(x) __builtin_expect ((x), 0)
#  define arg_unused __attribute__ ((unused))
#else
#  define LIKELY(x) (x)
#  define UNLIKELY(x) (x)
#  define arg_unused
#endif

#define OOM()                            \
  do                                     \
    {                                    \
      fprintf (stderr, "out of memory"); \
      _exit (EXIT_FAILURE);              \
  } while (0)

#define crun_make_error libcrun_make_error

__attribute__ ((malloc)) static inline void *
xmalloc (size_t size)
{
  void *res = malloc (size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

__attribute__ ((malloc)) static inline void *
xmalloc0 (size_t size)
{
  void *res = calloc (1, size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

__attribute__ ((malloc)) static inline void *
xrealloc (void *ptr, size_t size)
{
  void *res = realloc (ptr, size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

static inline char *
xstrdup (const char *str)
{
  char *ret;
  if (str == NULL)
    return NULL;
  ret = strdup (str);
  if (UNLIKELY (ret == NULL))
    OOM ();
  return ret;
}

static inline void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

static inline void
cleanup_filep (FILE **f)
{
  FILE *file = *f;
  if (file)
    (void) fclose (file);
}

static inline void
cleanup_closep (void *p)
{
  int *pp = (int *) p;
  if (*pp >= 0)
    close (*pp);
}

#define cleanup_free __attribute__ ((cleanup (cleanup_freep)))
#define cleanup_file __attribute__ ((cleanup (cleanup_filep)))
#define cleanup_close __attribute__ ((cleanup (cleanup_closep)))

/* Relies on <libcrun.h> (included before this header via crun.h) for the
   opaque libcrun_context_t and libcrun_context_free.  */
static inline void
cleanup_libcrun_contextp (libcrun_context_t **p)
{
  if (*p)
    libcrun_context_free (*p);
}

#define cleanup_context __attribute__ ((cleanup (cleanup_libcrun_contextp)))

static inline void
cleanup_libcrun_containerp (libcrun_container_t **p)
{
  if (*p)
    libcrun_container_free (*p);
}

#define cleanup_container __attribute__ ((cleanup (cleanup_libcrun_containerp)))

#endif
