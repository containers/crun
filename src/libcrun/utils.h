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
#ifndef UTILS_H
# define UTILS_H
# include <config.h>
# include <stdio.h>
# include <stdlib.h>
# include <error.h>
# include <errno.h>
# include <argp.h>

void cleanup_freep (void *p);

#define cleanup_free __attribute__((cleanup (cleanup_freep)))

# define LIKELY(x) __builtin_expect((x),1)
# define UNLIKELY(x) __builtin_expect((x),0)

# define OOM() do {error (EXIT_FAILURE, 0, "OOM");} while (0)

void *xmalloc (size_t size);

char *argp_mandatory_argument (char *arg, struct argp_state *state);

int crun_static_error (char **err, int status, const char *msg, ...);

int crun_path_exists (const char *path, int readonly, char **err);

#endif
