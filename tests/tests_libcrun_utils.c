/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
 * libocispec is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libocispec is distributed in the hope that it will be useful,
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

typedef int (*test)();

static int
test_run_process ()
{
  libcrun_error_t err = NULL;
  {
    char *args[] = {"/bin/true", NULL};
    if (run_process (args, &err) != 0)
      return -1;
  }

  {
    char *args[] = {"/bin/false", NULL};
    if (run_process (args, &err) <= 0)
      return -1;
    if (err != NULL)
      return -1;
  }

  {
    char *args[] = {"/does/not/exist", NULL};
    int r = run_process (args, &err);
    if (r <= 0)
      return -1;
    if (err != NULL)
      return -1;
  }

  return 0;
}

static int
test_dir_p ()
{
  libcrun_error_t err;
  if (crun_dir_p ("/usr", &err) <= 0)
    return -1;
  if (crun_dir_p ("/usr/bin/ls", &err) != 0)
    return -1;
  if (crun_dir_p ("/hopefully/does/not/really/exist", &err) >= 0)
    return -1;
  return 0;
}

static int
test_write_read_file ()
{
  libcrun_error_t err;
  cleanup_free char *name = NULL;
  size_t len;
  int i;
  int ret, failed = 0;
  size_t max = 1 << 10;
  cleanup_free char *written = xmalloc (max);

  xasprintf (&name, "tests/write-file-%i", getpid ());

  for (i = 0; i < max; i++)
    written[i] = i;

  for (i = 1; i <= max; i *= 2)
    {
      cleanup_free char *read_buf = NULL;

      ret = write_file (name, written, i, &err);
      if (ret < 0)
        {
          failed = 1;
          break;
        }
        
      ret = read_all_file (name, &read_buf, &len, &err);
      if (ret < 0)
        {
          failed = 1;
          break;
        }

      if (len != i)
        {
          failed = 1;
          break;
        }

      if (memcmp (read_buf, written, len) != 0)
        {
          failed = 1;
          break;
        }
    }

  unlink (name);
  return failed ? -1 : 0;
}

static int
test_crun_path_exists ()
{

  libcrun_error_t err;
  if (crun_path_exists ("/usr/bin/ls", 1, &err) <= 0)
    return -1;
  if (crun_path_exists ("/usr/foo/bin/ls", 1, &err) != 0)
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
  printf ("1..4\n");
  RUN_TEST (test_crun_path_exists);
  RUN_TEST (test_write_read_file);
  RUN_TEST (test_run_process);
  RUN_TEST (test_dir_p);
  return 0;
}
