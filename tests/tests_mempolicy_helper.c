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

#include <config.h>

#ifdef HAVE_NUMA
#  include <stdio.h>
#  include <numaif.h>
#  include "mempolicy_internal.h"

static void
mpol_print_features (const str2int_map_t *map)
{
  int idx = 0;

  while (map[idx].name != NULL)
    {
      printf ("%s\n", map[idx].name);
      idx++;
    }
  return;
}
#endif

int
main ()
{
#ifdef HAVE_NUMA
  mpol_print_features (mpol_mode_map);
  mpol_print_features (mpol_flag_map);
#endif
  return 0;
}
