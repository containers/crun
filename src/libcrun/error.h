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
#ifndef ERROR_H
# define ERROR_H
# include <config.h>
# include <error.h>
# include <stdlib.h>

struct libcrun_error_s
{
  int status;
  char *msg;
};
typedef struct libcrun_error_s *libcrun_error_t;

# define OOM() do {error (EXIT_FAILURE, 0, "OOM");} while (0)

int crun_make_error (libcrun_error_t *err, int status, const char *msg, ...);

int crun_error_release (libcrun_error_t *err);

#endif
