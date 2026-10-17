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

#ifndef TAP_H
#define TAP_H

#include <stdio.h>

typedef int (*test) ();

static int tap_tests_run;

static void
run_and_print_test_result (const char *name, test t)
{
  int id = ++tap_tests_run;
  int ret = t ();
  if (ret == 0)
    printf ("ok %d - %s\n", id, name);
  else if (ret == 77)
    printf ("ok %d - %s #SKIP\n", id, name);
  else
    printf ("not ok %d - %s\n", id, name);
}

#define RUN_TEST(T) run_and_print_test_result (#T, T)

/* Print the TAP plan; must be called after all tests are run.  */
static void
print_tap_plan ()
{
  printf ("1..%d\n", tap_tests_run);
}

#endif
