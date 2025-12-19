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

#include <libcrun/mount_flags.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

typedef int (*test) ();

/* Test that known flags are found */
static int
test_known_flags_found ()
{
  const struct propagation_flags_s *flag;

  /* These are all defined in mount_flags.perf */
  flag = libcrun_str2mount_flags ("bind");
  if (flag == NULL)
    return -1;

  flag = libcrun_str2mount_flags ("ro");
  if (flag == NULL)
    return -1;

  flag = libcrun_str2mount_flags ("rw");
  if (flag == NULL)
    return -1;

  flag = libcrun_str2mount_flags ("nosuid");
  if (flag == NULL)
    return -1;

  flag = libcrun_str2mount_flags ("nodev");
  if (flag == NULL)
    return -1;

  flag = libcrun_str2mount_flags ("noexec");
  if (flag == NULL)
    return -1;

  flag = libcrun_str2mount_flags ("shared");
  if (flag == NULL)
    return -1;

  flag = libcrun_str2mount_flags ("private");
  if (flag == NULL)
    return -1;

  flag = libcrun_str2mount_flags ("defaults");
  if (flag == NULL)
    return -1;

  return 0;
}

/* Test that unknown flags return NULL */
static int
test_unknown_flags ()
{
  const struct propagation_flags_s *flag;

  flag = libcrun_str2mount_flags ("");
  if (flag != NULL)
    return -1;

  flag = libcrun_str2mount_flags ("unknown");
  if (flag != NULL)
    return -1;

  flag = libcrun_str2mount_flags ("BIND");
  if (flag != NULL)
    return -1;

  return 0;
}

/* Test flag name matches */
static int
test_flag_names ()
{
  const struct propagation_flags_s *flag;

  flag = libcrun_str2mount_flags ("bind");
  if (flag == NULL || strcmp (flag->name, "bind") != 0)
    return -1;

  flag = libcrun_str2mount_flags ("ro");
  if (flag == NULL || strcmp (flag->name, "ro") != 0)
    return -1;

  flag = libcrun_str2mount_flags ("defaults");
  if (flag == NULL || strcmp (flag->name, "defaults") != 0)
    return -1;

  return 0;
}

/* Test clear field for rw vs ro */
static int
test_clear_field ()
{
  const struct propagation_flags_s *flag;

  /* ro should NOT have clear set */
  flag = libcrun_str2mount_flags ("ro");
  if (flag == NULL || flag->clear != 0)
    return -1;

  /* rw SHOULD have clear set */
  flag = libcrun_str2mount_flags ("rw");
  if (flag == NULL || flag->clear != 1)
    return -1;

  return 0;
}

/* Test special options have extra_flags set */
static int
test_extra_flags ()
{
  const struct propagation_flags_s *flag;

  flag = libcrun_str2mount_flags ("tmpcopyup");
  if (flag == NULL || flag->extra_flags != OPTION_TMPCOPYUP)
    return -1;

  flag = libcrun_str2mount_flags ("idmap");
  if (flag == NULL || flag->extra_flags != OPTION_IDMAP)
    return -1;

  flag = libcrun_str2mount_flags ("rro");
  if (flag == NULL || flag->extra_flags != OPTION_RECURSIVE)
    return -1;

  return 0;
}

static void
run_and_print_test_result (const char *name, int id, test t)
{
  int ret = t ();
  if (ret == 0)
    printf ("ok %d - %s\n", id, name);
  else if (ret == 77)
    printf ("ok %d - %s #SKIP\n", id, name);
  else
    printf ("not ok %d - %s\n", id, name);
}

#define RUN_TEST(T)                            \
  do                                           \
    {                                          \
      run_and_print_test_result (#T, id++, T); \
    }                                          \
  while (0)

int
main ()
{
  int id = 1;
  printf ("1..5\n");
  RUN_TEST (test_known_flags_found);
  RUN_TEST (test_unknown_flags);
  RUN_TEST (test_flag_names);
  RUN_TEST (test_clear_field);
  RUN_TEST (test_extra_flags);
  return 0;
}
