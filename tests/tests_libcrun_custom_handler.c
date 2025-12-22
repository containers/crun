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

#include <libcrun/error.h>
#include <libcrun/custom-handler.h>
#include <stdio.h>

typedef int (*test) ();

/* Test handler manager create and free */
static int
test_handler_manager_create_free ()
{
  libcrun_error_t err = NULL;
  struct custom_handler_manager_s *manager;

  manager = libcrun_handler_manager_create (&err);
  if (manager == NULL)
    {
      crun_error_release (&err);
      return -1;
    }

  handler_manager_free (manager);

  /* Test freeing NULL - should not crash */
  handler_manager_free (NULL);

  return 0;
}

/* Test handler_by_name with non-existent handler */
static int
test_handler_by_name_not_found ()
{
  libcrun_error_t err = NULL;
  struct custom_handler_manager_s *manager;
  struct custom_handler_s *h;

  manager = libcrun_handler_manager_create (&err);
  if (manager == NULL)
    {
      crun_error_release (&err);
      return -1;
    }

  /* Search for non-existent handler should return NULL */
  h = handler_by_name (manager, "nonexistent");
  if (h != NULL)
    {
      handler_manager_free (manager);
      return -1;
    }

  handler_manager_free (manager);
  return 0;
}

/* Test handler_by_name with empty name */
static int
test_handler_by_name_empty ()
{
  libcrun_error_t err = NULL;
  struct custom_handler_manager_s *manager;
  struct custom_handler_s *h;

  manager = libcrun_handler_manager_create (&err);
  if (manager == NULL)
    {
      crun_error_release (&err);
      return -1;
    }

  /* Empty name should return NULL without crashing */
  h = handler_by_name (manager, "");
  if (h != NULL)
    {
      handler_manager_free (manager);
      return -1;
    }

  handler_manager_free (manager);
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
  printf ("1..3\n");

  RUN_TEST (test_handler_manager_create_free);
  RUN_TEST (test_handler_by_name_not_found);
  RUN_TEST (test_handler_by_name_empty);

  return 0;
}
