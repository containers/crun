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

#define _GNU_SOURCE
#include <config.h>
#include <stdio.h>
#include <libcrun/error.h>
#include <libcrun/utils.h>
#include <libcrun/linux.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <limits.h>
#include <ocispec/runtime_spec_schema_config_schema.h>

/* Ensure namespace constants are defined */
#ifndef CLONE_NEWNS
#  define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWNET
#  define CLONE_NEWNET 0x40000000
#endif
#ifndef CLONE_NEWIPC
#  define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWPID
#  define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWUTS
#  define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWUSER
#  define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWCGROUP
#  define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWTIME
#  define CLONE_NEWTIME 0x00000080
#endif

typedef int (*test) ();

/* Test libcrun_find_namespace function */
static int
test_find_namespace ()
{
  int ret;

  /* Test valid namespace names */
  ret = libcrun_find_namespace ("mount");
  if (ret != CLONE_NEWNS)
    return -1;

  ret = libcrun_find_namespace ("network");
  if (ret != CLONE_NEWNET)
    return -1;

  ret = libcrun_find_namespace ("ipc");
  if (ret != CLONE_NEWIPC)
    return -1;

  ret = libcrun_find_namespace ("pid");
  if (ret != CLONE_NEWPID)
    return -1;

  ret = libcrun_find_namespace ("uts");
  if (ret != CLONE_NEWUTS)
    return -1;

  ret = libcrun_find_namespace ("user");
  if (ret != CLONE_NEWUSER)
    return -1;

#ifdef CLONE_NEWCGROUP
  ret = libcrun_find_namespace ("cgroup");
  if (ret != CLONE_NEWCGROUP)
    return -1;
#endif

#ifdef CLONE_NEWTIME
  ret = libcrun_find_namespace ("time");
  if (ret != CLONE_NEWTIME)
    return -1;
#endif

  /* Test invalid namespace name */
  ret = libcrun_find_namespace ("invalid");
  if (ret != -1)
    return -1;

  ret = libcrun_find_namespace ("");
  if (ret != -1)
    return -1;

  /* Note: Do NOT test NULL - libcrun_find_namespace likely doesn't handle NULL */

  return 0;
}

/* Test path_is_slash_dev function (from utils.h but used heavily in linux.c) */
static int
test_path_is_slash_dev_linux ()
{
  /* Test exact /dev */
  if (! path_is_slash_dev ("/dev"))
    return -1;
  if (! path_is_slash_dev ("/dev/"))
    return -1;
  if (! path_is_slash_dev ("dev"))
    return -1;
  if (! path_is_slash_dev ("dev/"))
    return -1;

  /* Test with extra slashes */
  if (! path_is_slash_dev ("/dev//"))
    return -1;
  if (! path_is_slash_dev ("///dev///"))
    return -1;

  /* Test subdirectories of /dev - should fail */
  if (path_is_slash_dev ("/dev/null"))
    return -1;
  if (path_is_slash_dev ("/dev/pts"))
    return -1;
  if (path_is_slash_dev ("/dev/pts/0"))
    return -1;

  /* Test other paths */
  if (path_is_slash_dev ("/"))
    return -1;
  if (path_is_slash_dev ("/home"))
    return -1;
  if (path_is_slash_dev (""))
    return -1;

  return 0;
}

/* Test libcrun_reopen_dev_null function */
static int
test_reopen_dev_null ()
{
  libcrun_error_t err = NULL;
  int ret;
  int saved_stdin, saved_stdout, saved_stderr;

  /* Save current stdin/stdout/stderr */
  saved_stdin = dup (0);
  saved_stdout = dup (1);
  saved_stderr = dup (2);

  if (saved_stdin < 0 || saved_stdout < 0 || saved_stderr < 0)
    {
      /* Cleanup on failure */
      if (saved_stdin >= 0)
        close (saved_stdin);
      if (saved_stdout >= 0)
        close (saved_stdout);
      if (saved_stderr >= 0)
        close (saved_stderr);
      return 77; /* SKIP - can't save descriptors */
    }

  /* Call the function */
  ret = libcrun_reopen_dev_null (&err);

  /* Restore original descriptors */
  dup2 (saved_stdin, 0);
  dup2 (saved_stdout, 1);
  dup2 (saved_stderr, 2);
  close (saved_stdin);
  close (saved_stdout);
  close (saved_stderr);

  if (ret < 0)
    {
      crun_error_release (&err);
      return -1;
    }

  return 0;
}

/* Test libcrun_set_rlimits function */
static int
test_set_rlimits ()
{
  libcrun_error_t err = NULL;
  int ret;
  struct rlimit current_nofile;

  /* Get current NOFILE limit to restore later */
  if (getrlimit (RLIMIT_NOFILE, &current_nofile) < 0)
    return 77; /* SKIP */

  /* Test with NULL rlimits - should succeed */
  ret = libcrun_set_rlimits (NULL, 0, &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      return -1;
    }

  /* Restore original limit */
  setrlimit (RLIMIT_NOFILE, &current_nofile);

  return 0;
}

/* Test libcrun_find_namespace with edge cases */
static int
test_find_namespace_edge_cases ()
{
  int ret;

  /* Test with partial names - should fail */
  ret = libcrun_find_namespace ("moun");
  if (ret != -1)
    return -1;

  ret = libcrun_find_namespace ("networ");
  if (ret != -1)
    return -1;

  /* Test with wrong case - should fail */
  ret = libcrun_find_namespace ("MOUNT");
  if (ret != -1)
    return -1;

  ret = libcrun_find_namespace ("Network");
  if (ret != -1)
    return -1;

  /* Test with extra characters */
  ret = libcrun_find_namespace ("mount ");
  if (ret != -1)
    return -1;

  ret = libcrun_find_namespace (" mount");
  if (ret != -1)
    return -1;

  return 0;
}

/* Test path boundary conditions */
static int
test_path_boundary ()
{
  /* Test paths that start with dev but aren't /dev */
  if (path_is_slash_dev ("devious"))
    return -1;

  if (path_is_slash_dev ("developer"))
    return -1;

  /* Various forms of /dev */
  if (! path_is_slash_dev ("/dev"))
    return -1;

  return 0;
}

/* Test libcrun_safe_chdir function */
static int
test_safe_chdir ()
{
  libcrun_error_t err = NULL;
  char saved_cwd[PATH_MAX];
  int ret;

  /* Save current directory */
  if (getcwd (saved_cwd, sizeof (saved_cwd)) == NULL)
    return 77; /* SKIP */

  /* Test with valid directory */
  ret = libcrun_safe_chdir ("/tmp", &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      /* Restore cwd */
      if (chdir (saved_cwd) < 0)
        {
          /* ignore */
        }
      return -1;
    }

  /* Test with another valid directory */
  ret = libcrun_safe_chdir ("/", &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      if (chdir (saved_cwd) < 0)
        {
          /* ignore */
        }
      return -1;
    }

  /* Test with non-existent directory - should fail */
  ret = libcrun_safe_chdir ("/nonexistent_directory_12345", &err);
  if (ret >= 0)
    {
      /* Should have failed */
      if (chdir (saved_cwd) < 0)
        {
          /* ignore */
        }
      return -1;
    }
  crun_error_release (&err);

  /* Restore original directory */
  if (chdir (saved_cwd) < 0)
    return -1;

  return 0;
}

/* Test syscall_clone inline function indirectly by checking it compiles and constants are correct */
static int
test_clone_constants ()
{
  /* Just verify the constants are defined correctly - we can't actually call clone without side effects */
  if (CLONE_NEWNS == 0)
    return -1;
  if (CLONE_NEWNET == 0)
    return -1;
  if (CLONE_NEWIPC == 0)
    return -1;
  if (CLONE_NEWPID == 0)
    return -1;
  if (CLONE_NEWUTS == 0)
    return -1;
  if (CLONE_NEWUSER == 0)
    return -1;

  /* Verify namespace values are different */
  if (CLONE_NEWNS == CLONE_NEWNET)
    return -1;
  if (CLONE_NEWNS == CLONE_NEWIPC)
    return -1;
  if (CLONE_NEWNET == CLONE_NEWPID)
    return -1;

  return 0;
}

/* Test that namespace lookup is consistent */
static int
test_namespace_consistency ()
{
  /* Verify that libcrun_find_namespace returns the expected clone flags */
  int mount_val = libcrun_find_namespace ("mount");
  int net_val = libcrun_find_namespace ("network");
  int pid_val = libcrun_find_namespace ("pid");
  int user_val = libcrun_find_namespace ("user");

  /* All should be non-zero (valid namespaces) */
  if (mount_val == 0 || net_val == 0 || pid_val == 0 || user_val == 0)
    return -1;

  /* All should be different */
  if (mount_val == net_val || mount_val == pid_val || mount_val == user_val)
    return -1;
  if (net_val == pid_val || net_val == user_val)
    return -1;
  if (pid_val == user_val)
    return -1;

  return 0;
}

/* Test rlimits with zero length */
static int
test_rlimits_zero_length ()
{
  libcrun_error_t err = NULL;
  runtime_spec_schema_config_schema_process_rlimits_element *rlimits[1] = { NULL };
  int ret;

  /* Test with empty array */
  ret = libcrun_set_rlimits (rlimits, 0, &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      return -1;
    }

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
  RUN_TEST (test_find_namespace);
  RUN_TEST (test_path_is_slash_dev_linux);
  RUN_TEST (test_reopen_dev_null);
  RUN_TEST (test_set_rlimits);
  RUN_TEST (test_find_namespace_edge_cases);
  RUN_TEST (test_path_boundary);
  RUN_TEST (test_safe_chdir);
  RUN_TEST (test_clone_constants);
  RUN_TEST (test_namespace_consistency);
  RUN_TEST (test_rlimits_zero_length);
  return 0;
}
