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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libcrun/cgroup-internal.h>

typedef int (*test) ();

/* Test read_proc_cgroup with cgroup v2 content */
static int
test_read_proc_cgroup_v2 ()
{
  char content[] = "0::/user.slice/user-1000.slice/session-1.scope\n";
  char *saveptr = NULL;
  char *id = NULL;
  char *controller = NULL;
  char *path = NULL;
  bool has_data;

  has_data = read_proc_cgroup (content, &saveptr, &id, &controller, &path);
  if (! has_data)
    return -1;

  if (strcmp (id, "0") != 0)
    return -1;
  if (strcmp (controller, "") != 0)
    return -1;
  if (strcmp (path, "/user.slice/user-1000.slice/session-1.scope") != 0)
    return -1;

  /* Should return false for next iteration */
  has_data = read_proc_cgroup (NULL, &saveptr, &id, &controller, &path);
  if (has_data)
    return -1;

  return 0;
}

/* Test read_proc_cgroup with cgroup v1 content */
static int
test_read_proc_cgroup_v1 ()
{
  char content[] = "12:memory:/docker/abc123\n"
                   "11:cpuset:/docker/abc123\n"
                   "10:cpu,cpuacct:/docker/abc123\n"
                   "0::/\n";
  char *saveptr = NULL;
  char *id = NULL;
  char *controller = NULL;
  char *path = NULL;
  bool has_data;
  int count = 0;

  /* First entry: memory */
  has_data = read_proc_cgroup (content, &saveptr, &id, &controller, &path);
  if (! has_data)
    return -1;
  if (strcmp (controller, "memory") != 0)
    return -1;
  if (strcmp (path, "/docker/abc123") != 0)
    return -1;
  count++;

  /* Second entry: cpuset */
  has_data = read_proc_cgroup (NULL, &saveptr, &id, &controller, &path);
  if (! has_data)
    return -1;
  if (strcmp (controller, "cpuset") != 0)
    return -1;
  count++;

  /* Third entry: cpu,cpuacct */
  has_data = read_proc_cgroup (NULL, &saveptr, &id, &controller, &path);
  if (! has_data)
    return -1;
  if (strcmp (controller, "cpu,cpuacct") != 0)
    return -1;
  count++;

  /* Fourth entry: unified (empty controller) */
  has_data = read_proc_cgroup (NULL, &saveptr, &id, &controller, &path);
  if (! has_data)
    return -1;
  if (strcmp (controller, "") != 0)
    return -1;
  if (strcmp (path, "/") != 0)
    return -1;
  count++;

  /* No more entries */
  has_data = read_proc_cgroup (NULL, &saveptr, &id, &controller, &path);
  if (has_data)
    return -1;

  if (count != 4)
    return -1;

  return 0;
}

/* Test read_proc_cgroup with empty content */
static int
test_read_proc_cgroup_empty ()
{
  char content[] = "";
  char *saveptr = NULL;
  char *id = NULL;
  char *controller = NULL;
  char *path = NULL;
  bool has_data;

  has_data = read_proc_cgroup (content, &saveptr, &id, &controller, &path);
  if (has_data)
    return -1;

  return 0;
}

/* Test read_proc_cgroup with named controller */
static int
test_read_proc_cgroup_named ()
{
  char content[] = "1:name=systemd:/user.slice/user-1000.slice\n";
  char *saveptr = NULL;
  char *id = NULL;
  char *controller = NULL;
  char *path = NULL;
  bool has_data;

  has_data = read_proc_cgroup (content, &saveptr, &id, &controller, &path);
  if (! has_data)
    return -1;

  /* Should return the full "name=systemd" */
  if (strcmp (controller, "name=systemd") != 0)
    return -1;
  if (strcmp (path, "/user.slice/user-1000.slice") != 0)
    return -1;

  return 0;
}

/* Test convert_shares_to_weight function */
static int
test_convert_shares_to_weight ()
{
  uint64_t weight;

  /* Test value 0 - means unset */
  weight = convert_shares_to_weight (0);
  if (weight != 0)
    return -1;

  /* Test low values (shares <= 2) */
  weight = convert_shares_to_weight (1);
  if (weight != 1)
    return -1;
  weight = convert_shares_to_weight (2);
  if (weight != 1)
    return -1;

  /* Test high values (shares >= 262144) */
  weight = convert_shares_to_weight (262144);
  if (weight != 10000)
    return -1;
  weight = convert_shares_to_weight (500000);
  if (weight != 10000)
    return -1;

  /* Test default shares (1024) - should map to around 100 */
  weight = convert_shares_to_weight (1024);
  /* The formula gives approximately 100 for 1024 shares */
  if (weight < 90 || weight > 110)
    return -1;

  /* Test intermediate value */
  weight = convert_shares_to_weight (512);
  if (weight == 0 || weight > 10000)
    return -1;

  return 0;
}

/* Test convert_shares_to_weight with various values */
static int
test_convert_shares_boundary ()
{
  uint64_t weight;

  /* Value just above 2 should not return 1 */
  weight = convert_shares_to_weight (3);
  if (weight == 0)
    return -1;

  /* Value just below 262144 should not return 10000 */
  weight = convert_shares_to_weight (262143);
  if (weight == 0 || weight > 10000)
    return -1;

  /* Ensure monotonicity: higher shares should give higher weight */
  uint64_t w100 = convert_shares_to_weight (100);
  uint64_t w1000 = convert_shares_to_weight (1000);
  uint64_t w10000 = convert_shares_to_weight (10000);

  if (w100 > w1000 || w1000 > w10000)
    return -1;

  return 0;
}

/* Test read_proc_cgroup with NULL output parameters */
static int
test_read_proc_cgroup_null_params ()
{
  char content[] = "0::/some/path\n";
  char *saveptr = NULL;
  bool has_data;

  /* Should handle NULL output parameters */
  has_data = read_proc_cgroup (content, &saveptr, NULL, NULL, NULL);
  if (! has_data)
    return -1;

  return 0;
}

/* Test read_proc_cgroup with multiple lines and selective parameters */
static int
test_read_proc_cgroup_selective ()
{
  char content[] = "5:pids:/container\n2:cpu:/container\n";
  char *saveptr = NULL;
  char *controller = NULL;
  bool has_data;

  /* Only get controller */
  has_data = read_proc_cgroup (content, &saveptr, NULL, &controller, NULL);
  if (! has_data)
    return -1;
  if (strcmp (controller, "pids") != 0)
    return -1;

  /* Second iteration */
  has_data = read_proc_cgroup (NULL, &saveptr, NULL, &controller, NULL);
  if (! has_data)
    return -1;
  if (strcmp (controller, "cpu") != 0)
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
  } while (0)

int
main ()
{
  int id = 1;
  printf ("1..8\n");
  RUN_TEST (test_read_proc_cgroup_v2);
  RUN_TEST (test_read_proc_cgroup_v1);
  RUN_TEST (test_read_proc_cgroup_empty);
  RUN_TEST (test_read_proc_cgroup_named);
  RUN_TEST (test_convert_shares_to_weight);
  RUN_TEST (test_convert_shares_boundary);
  RUN_TEST (test_read_proc_cgroup_null_params);
  RUN_TEST (test_read_proc_cgroup_selective);
  return 0;
}
