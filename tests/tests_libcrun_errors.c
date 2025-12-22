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
#include <libcrun/utils.h>
#include <string.h>

typedef int (*test) ();

static int
test_crun_make_error ()
{

  libcrun_error_t err = NULL;
  int ret = crun_make_error (&err, 12, "HELLO %s", "WORLD");
  if (ret >= 0)
    return -1;

  if (err->status != 12)
    return -1;

  if (strcmp (err->msg, "HELLO WORLD") != 0)
    return -1;

  crun_error_release (&err);

  return 0;
}

static int
test_crun_write_warning_and_release ()
{

  libcrun_error_t err_data = NULL;
  libcrun_error_t *err = &err_data;
  cleanup_free char *buffer = NULL;
  size_t len;
  FILE *stream;

  int ret = crun_make_error (err, 0, "HELLO %s", "WORLD");
  if (ret >= 0)
    return -1;

  if ((*err)->status != 0)
    return -1;
  if ((*err)->msg == NULL)
    return -1;

  stream = open_memstream (&buffer, &len);
  crun_error_write_warning_and_release (stream, &err);
  fclose (stream);

  if (len != 12)
    return -1;

  if (*err)
    return -1;

  if (strcmp (buffer, "HELLO WORLD\n") != 0)
    return -1;

  return 0;
}

static int
test_crun_error_wrap ()
{
  libcrun_error_t err = NULL;
  int ret;

  ret = crun_make_error (&err, 5, "inner error");
  if (ret >= 0)
    return -1;

  ret = crun_error_wrap (&err, "outer context");
  if (ret >= 0)
    return -1;

  if (err->status != 5)
    return -1;

  /* Message should be "outer context: inner error" */
  if (strstr (err->msg, "outer context") == NULL)
    return -1;
  if (strstr (err->msg, "inner error") == NULL)
    return -1;

  crun_error_release (&err);

  /* Test with NULL error */
  ret = crun_error_wrap (NULL, "should not crash");
  if (ret != 0)
    return -1;

  return 0;
}

static int
test_crun_error_get_errno ()
{
  libcrun_error_t err = NULL;
  int ret;

  /* Test with NULL */
  ret = crun_error_get_errno (NULL);
  if (ret != 0)
    return -1;

  /* Test with NULL pointer */
  ret = crun_error_get_errno (&err);
  if (ret != 0)
    return -1;

  /* Test with actual error */
  crun_make_error (&err, 42, "test error");
  ret = crun_error_get_errno (&err);
  if (ret != 42)
    return -1;

  crun_error_release (&err);
  return 0;
}

static int
test_libcrun_verbosity ()
{
  int orig = libcrun_get_verbosity ();

  libcrun_set_verbosity (LIBCRUN_VERBOSITY_WARNING);
  if (libcrun_get_verbosity () != LIBCRUN_VERBOSITY_WARNING)
    return -1;

  libcrun_set_verbosity (LIBCRUN_VERBOSITY_DEBUG);
  if (libcrun_get_verbosity () != LIBCRUN_VERBOSITY_DEBUG)
    return -1;

  libcrun_set_verbosity (LIBCRUN_VERBOSITY_ERROR);
  if (libcrun_get_verbosity () != LIBCRUN_VERBOSITY_ERROR)
    return -1;

  /* Restore original */
  libcrun_set_verbosity (orig);
  return 0;
}

static int
test_libcrun_set_log_format ()
{
  libcrun_error_t err = NULL;
  int ret;

  /* Test valid formats */
  ret = libcrun_set_log_format ("text", &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      return -1;
    }

  ret = libcrun_set_log_format ("json", &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      return -1;
    }

  /* Test invalid format */
  ret = libcrun_set_log_format ("invalid", &err);
  if (ret >= 0)
    return -1;

  crun_error_release (&err);

  /* Restore to text */
  libcrun_set_log_format ("text", &err);
  crun_error_release (&err);

  return 0;
}

static int
test_crun_error_release_null ()
{
  libcrun_error_t err = NULL;
  int ret;

  /* Should handle NULL gracefully */
  ret = crun_error_release (NULL);
  if (ret != 0)
    return -1;

  /* Should handle pointer to NULL gracefully */
  ret = crun_error_release (&err);
  if (ret != 0)
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
  printf ("1..7\n");
  RUN_TEST (test_crun_make_error);
  RUN_TEST (test_crun_write_warning_and_release);
  RUN_TEST (test_crun_error_wrap);
  RUN_TEST (test_crun_error_get_errno);
  RUN_TEST (test_libcrun_verbosity);
  RUN_TEST (test_libcrun_set_log_format);
  RUN_TEST (test_crun_error_release_null);
  return 0;
}
