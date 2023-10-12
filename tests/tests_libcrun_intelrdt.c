/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2023 Giuseppe Scrivano <giuseppe@scrivano.org>
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

#include <libcrun/error.h>
#include <libcrun/utils.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

typedef int (*test) ();

extern int compare_rdt_configurations (const char *a, const char *b);
extern char *intelrdt_clean_l3_cache_schema (const char *l3_cache_schema);

static int
test_compare_rdt_configurations ()
{
  if (compare_rdt_configurations ("L3:1=1f;0=7f0;", "L3:0=7f0;1=01f;"))
    return 1;
  if (compare_rdt_configurations ("L3:1=1f;0=7f0;", "L3:0=7f0;1=01f"))
    return 1;
  if (compare_rdt_configurations ("MB:0=20;1=70", "MB:0=20;1=70"))
    return 1;
  if (compare_rdt_configurations ("MB:0=20;1=70;", "0= 20;1= 70"))
    return 1;
  return 0;
}

static int
test_intelrdt_clean_l3_cache_schema ()
{
#define COMPARE(X, Y)                                 \
  do                                                  \
    {                                                 \
      char *res = intelrdt_clean_l3_cache_schema (X); \
      int r = strcmp (res, Y);                        \
      free (res);                                     \
      if (r)                                          \
        return 1;                                     \
  } while (0)

  COMPARE ("L3:2=2e;1=8e1;", "L3:2=2e;1=8e1;");
  COMPARE ("L3:2=2e;1=8e1", "L3:2=2e;1=8e1");
  COMPARE ("L3:2=2e;1=8e1;\nMB:13", "L3:2=2e;1=8e1;\n");
  COMPARE ("MB:13\nL3:2=2e;1=8e1", "L3:2=2e;1=8e1");
  COMPARE ("L3:2=2e;1=8e1\nMB:foo1=bar1\n", "L3:2=2e;1=8e1\n");
  COMPARE ("L3:3=3d;2=9d2;", "L3:3=3d;2=9d2;");
  COMPARE ("L3:3=3d;2=9d2", "L3:3=3d;2=9d2");
  COMPARE ("L3:3=3d;2=9d2;\nMB:14", "L3:3=3d;2=9d2;\n");
  COMPARE ("MB:14\nL3:3=3d;2=9d2", "L3:3=3d;2=9d2");
  COMPARE ("L3:3=3d;2=9d2\nMB:foo2=bar2\n", "L3:3=3d;2=9d2\n");
  COMPARE ("L3:4=4c;3=ac3;", "L3:4=4c;3=ac3;");
  COMPARE ("L3:4=4c;3=ac3", "L3:4=4c;3=ac3");
  COMPARE ("L3:4=4c;3=ac3;\nMB:15", "L3:4=4c;3=ac3;\n");
  COMPARE ("MB:15\nL3:4=4c;3=ac3", "L3:4=4c;3=ac3");
  COMPARE ("L3:4=4c;3=ac3\nMB:foo3=bar3\n", "L3:4=4c;3=ac3\n");

#undef COMPARE

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
  } while (0)

int
main ()
{
  int id = 1;
  printf ("1..2\n");
  RUN_TEST (test_compare_rdt_configurations);
  RUN_TEST (test_intelrdt_clean_l3_cache_schema);
  return 0;
}
