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
#include <libcrun/seccomp_notify.h>
#include <libcrun/error.h>
#include <errno.h>

typedef int (*test) ();

/* Test cleanup function with NULL */
static int
test_cleanup_null ()
{
  struct seccomp_notify_context_s *ctx = NULL;

  /* Should handle NULL without crashing */
  cleanup_seccomp_notify_pluginsp (&ctx);

  return 0;
}

/* Test free with NULL context */
static int
test_free_null_context ()
{
  libcrun_error_t err = NULL;
  int ret;
  int errnum;

  ret = libcrun_free_seccomp_notify_plugins (NULL, &err);

  /* Should return error for NULL context */
  if (ret >= 0)
    {
      crun_error_release (&err);
      return -1;
    }

  errnum = crun_error_get_errno (&err);
  /* With seccomp support: returns EINVAL for NULL context */
  /* Without seccomp support: returns ENOTSUP */
  if (errnum != EINVAL && errnum != ENOTSUP)
    {
      crun_error_release (&err);
      return -1;
    }

  crun_error_release (&err);
  return 0;
}

/* Test load with invalid plugin path */
static int
test_load_invalid_path ()
{
  libcrun_error_t err = NULL;
  struct seccomp_notify_context_s *ctx = NULL;
  int ret;

  /* Relative path with / should be rejected */
  ret = libcrun_load_seccomp_notify_plugins (&ctx, "./invalid/path.so", NULL, &err);

  /* Should fail - either ENOTSUP (no seccomp support) or error about relative path */
  if (ret >= 0)
    {
      if (ctx)
        libcrun_free_seccomp_notify_plugins (ctx, &err);
      crun_error_release (&err);
      return -1;
    }

  crun_error_release (&err);
  return 0;
}

/* Test load with non-existent plugin */
static int
test_load_nonexistent_plugin ()
{
  libcrun_error_t err = NULL;
  struct seccomp_notify_context_s *ctx = NULL;
  int ret;

  /* Absolute path to non-existent file */
  ret = libcrun_load_seccomp_notify_plugins (&ctx, "/nonexistent/plugin.so", NULL, &err);

  /* Should fail */
  if (ret >= 0)
    {
      if (ctx)
        libcrun_free_seccomp_notify_plugins (ctx, &err);
      crun_error_release (&err);
      return -1;
    }

  crun_error_release (&err);
  return 0;
}

/* Test seccomp_notify_plugins returns error without seccomp support */
static int
test_notify_no_seccomp ()
{
#if HAVE_DLOPEN && HAVE_SECCOMP_GET_NOTIF_SIZES && HAVE_SECCOMP
  /* With seccomp support, we can't test with NULL context as it would crash */
  /* Skip this test */
  return 77;
#else
  libcrun_error_t err = NULL;
  int ret;

  /* Without seccomp support, should return ENOTSUP even with NULL context */
  ret = libcrun_seccomp_notify_plugins (NULL, -1, &err);

  if (ret >= 0)
    {
      crun_error_release (&err);
      return -1;
    }
  if (crun_error_get_errno (&err) != ENOTSUP)
    {
      crun_error_release (&err);
      return -1;
    }

  crun_error_release (&err);
  return 0;
#endif
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
  printf ("1..5\n");
  RUN_TEST (test_cleanup_null);
  RUN_TEST (test_free_null_context);
  RUN_TEST (test_load_invalid_path);
  RUN_TEST (test_load_nonexistent_plugin);
  RUN_TEST (test_notify_no_seccomp);
  return 0;
}
