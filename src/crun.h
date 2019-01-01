/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#ifndef CRUN_H
# define CRUN_H

# include "libcrun/container.h"

struct crun_global_arguments
{
  char *root;
  char *log;

  bool command;
  bool debug;
  bool option_systemd_cgroup;
};

void init_libcrun_context (struct libcrun_context_s *con, const char *id, struct crun_global_arguments *glob);
void crun_assert_n_args (int n, int min, int max);
#endif
