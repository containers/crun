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

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>

typedef int (*test) ();

/* Defined in chroot_realpath.c */
char *chroot_realpath (const char *chroot, const char *path, char resolved_path[]);

/* Test trivial case: NULL chroot - just copies path */
static int
test_null_chroot ()
{
  char resolved[PATH_MAX];
  char *result;

  result = chroot_realpath (NULL, "/path/to/file", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/path/to/file") != 0)
    return -1;

  return 0;
}

/* Test trivial case: empty chroot - just copies path */
static int
test_empty_chroot ()
{
  char resolved[PATH_MAX];
  char *result;

  result = chroot_realpath ("", "/path/to/file", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/path/to/file") != 0)
    return -1;

  return 0;
}

/* Test trivial case: "/" chroot - just copies path */
static int
test_root_chroot ()
{
  char resolved[PATH_MAX];
  char *result;

  result = chroot_realpath ("/", "/path/to/file", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/path/to/file") != 0)
    return -1;

  return 0;
}

/* Test ENAMETOOLONG when path is too long */
static int
test_path_too_long ()
{
  char resolved[PATH_MAX];
  char *result;
  char long_path[PATH_MAX];

  /* Create a path that will exceed PATH_MAX when combined with chroot */
  memset (long_path, 'a', PATH_MAX - 1);
  long_path[0] = '/';
  long_path[PATH_MAX - 1] = '\0';

  errno = 0;
  result = chroot_realpath ("/chroot", long_path, resolved);
  if (result != NULL)
    return -1;
  if (errno != ENAMETOOLONG)
    return -1;

  return 0;
}

/* Test path with chroot prefix */
static int
test_with_chroot_prefix ()
{
  char resolved[PATH_MAX];
  char *result;

  result = chroot_realpath ("/myroot", "/path/to/file", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/myroot/path/to/file") != 0)
    return -1;

  return 0;
}

/* Test dot components . and .. using real existing paths */
static int
test_dot_components ()
{
  char resolved[PATH_MAX];
  char *result;

  /* Use /tmp as chroot since it exists on most systems */
  /* Test single dot - should be ignored */
  result = chroot_realpath ("/tmp", "/./file", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/tmp/file") != 0)
    return -1;

  /* Test double dot at root - should stay at root of chroot */
  result = chroot_realpath ("/tmp", "/../file", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/tmp/file") != 0)
    return -1;

  /* Test multiple .. at root */
  result = chroot_realpath ("/tmp", "/../../../file", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/tmp/file") != 0)
    return -1;

  return 0;
}

/* Test multiple slashes in path */
static int
test_multiple_slashes ()
{
  char resolved[PATH_MAX];
  char *result;

  /* Use /tmp as chroot since it exists */
  result = chroot_realpath ("/tmp", "///file", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/tmp/file") != 0)
    return -1;

  return 0;
}

/* Test simple relative-like path handling */
static int
test_simple_path ()
{
  char resolved[PATH_MAX];
  char *result;

  /* Just a simple filename */
  result = chroot_realpath ("/chroot", "/file", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/chroot/file") != 0)
    return -1;

  return 0;
}

/* Test path ending with slash */
static int
test_trailing_slash ()
{
  char resolved[PATH_MAX];
  char *result;

  result = chroot_realpath ("/chroot", "/path/to/dir/", resolved);
  if (result == NULL)
    return -1;
  /* The trailing slash should be handled */
  if (strncmp (resolved, "/chroot/path/to/dir", 19) != 0)
    return -1;

  return 0;
}

/* Test deeply nested path */
static int
test_deep_path ()
{
  char resolved[PATH_MAX];
  char *result;

  /* Use /tmp which is accessible to all users, unlike /root */
  result = chroot_realpath ("/tmp", "/a/b/c/d/e/f/g/h/i/j", resolved);
  if (result == NULL)
    return -1;
  if (strcmp (resolved, "/tmp/a/b/c/d/e/f/g/h/i/j") != 0)
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
  printf ("1..10\n");
  RUN_TEST (test_null_chroot);
  RUN_TEST (test_empty_chroot);
  RUN_TEST (test_root_chroot);
  RUN_TEST (test_path_too_long);
  RUN_TEST (test_with_chroot_prefix);
  RUN_TEST (test_dot_components);
  RUN_TEST (test_multiple_slashes);
  RUN_TEST (test_simple_path);
  RUN_TEST (test_trailing_slash);
  RUN_TEST (test_deep_path);
  return 0;
}
