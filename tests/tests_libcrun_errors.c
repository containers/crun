/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

typedef int (*test)();

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

#define RUN_TEST(T) do {run_and_print_test_result (#T, id++, T);} while (0)

int
main ()
{
  int id = 1;
  printf ("1..2\n");
  RUN_TEST (test_crun_make_error);
  RUN_TEST (test_crun_write_warning_and_release);
  return 0;
}
