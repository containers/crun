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
#include <libcrun/error.h>
#include <libcrun/terminal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

typedef int (*test) ();

/* Helper to create an isolated pty for testing */
static int
create_test_pty (int *master_fd, int *slave_fd)
{
  int mfd, sfd;
  char *slave_name;

  mfd = posix_openpt (O_RDWR | O_NOCTTY);
  if (mfd < 0)
    return -1;

  if (grantpt (mfd) < 0 || unlockpt (mfd) < 0)
    {
      close (mfd);
      return -1;
    }

  slave_name = ptsname (mfd);
  if (slave_name == NULL)
    {
      close (mfd);
      return -1;
    }

  sfd = open (slave_name, O_RDWR | O_NOCTTY);
  if (sfd < 0)
    {
      close (mfd);
      return -1;
    }

  *master_fd = mfd;
  *slave_fd = sfd;
  return 0;
}

/* Test cleanup_terminalp with NULL - should not crash */
static int
test_cleanup_terminalp_null ()
{
  void *status = NULL;
  cleanup_terminalp (&status);
  return 0;
}

/* Test libcrun_terminal_setup_size with invalid fd */
static int
test_terminal_setup_size_invalid_fd ()
{
  libcrun_error_t err = NULL;
  int ret;

  ret = libcrun_terminal_setup_size (-1, 24, 80, &err);
  if (ret >= 0)
    return -1;

  crun_error_release (&err);
  return 0;
}

/* Test libcrun_terminal_setup_size with isolated pty */
static int
test_terminal_setup_size_pty ()
{
  libcrun_error_t err = NULL;
  int master_fd, slave_fd;
  int ret;
  struct winsize ws;

  if (create_test_pty (&master_fd, &slave_fd) < 0)
    return 77; /* Skip if can't create pty */

  /* Set size on the slave (which is the terminal) */
  ret = libcrun_terminal_setup_size (slave_fd, 25, 80, &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      close (slave_fd);
      close (master_fd);
      return -1;
    }

  /* Verify the size was set */
  ret = ioctl (slave_fd, TIOCGWINSZ, &ws);
  close (slave_fd);
  close (master_fd);

  if (ret < 0)
    return -1;

  if (ws.ws_row != 25 || ws.ws_col != 80)
    return -1;

  return 0;
}

/* Test libcrun_set_raw with invalid fd */
static int
test_set_raw_invalid_fd ()
{
  libcrun_error_t err = NULL;
  void *status = NULL;
  int ret;

  ret = libcrun_set_raw (-1, &status, &err);
  if (ret >= 0)
    return -1;

  crun_error_release (&err);
  return 0;
}

/* Test libcrun_set_raw with isolated pty */
static int
test_set_raw_pty ()
{
  libcrun_error_t err = NULL;
  int master_fd, slave_fd;
  void *status = NULL;
  int ret;

  if (create_test_pty (&master_fd, &slave_fd) < 0)
    return 77; /* Skip if can't create pty */

  /* Set raw mode on the slave terminal */
  ret = libcrun_set_raw (slave_fd, &status, &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      close (slave_fd);
      close (master_fd);
      return -1;
    }

  /* Cleanup restores original settings */
  cleanup_terminalp (&status);

  close (slave_fd);
  close (master_fd);
  return 0;
}

/* Test libcrun_set_raw without saving status */
static int
test_set_raw_no_status ()
{
  libcrun_error_t err = NULL;
  int master_fd, slave_fd;
  int ret;

  if (create_test_pty (&master_fd, &slave_fd) < 0)
    return 77; /* Skip if can't create pty */

  /* Set raw mode without saving status */
  ret = libcrun_set_raw (slave_fd, NULL, &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      close (slave_fd);
      close (master_fd);
      return -1;
    }

  close (slave_fd);
  close (master_fd);
  return 0;
}

/* Test libcrun_new_terminal creates a valid pty */
static int
test_new_terminal ()
{
  libcrun_error_t err = NULL;
  char *pty = NULL;
  int ret;

  ret = libcrun_new_terminal (&pty, &err);
  if (ret < 0)
    {
      crun_error_release (&err);
      return -1;
    }

  /* Verify we got a valid pty path */
  if (pty == NULL || pty[0] != '/')
    {
      free (pty);
      close (ret);
      return -1;
    }

  /* Verify the master fd is valid */
  if (fcntl (ret, F_GETFD) < 0)
    {
      free (pty);
      close (ret);
      return -1;
    }

  free (pty);
  close (ret);
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
  RUN_TEST (test_cleanup_terminalp_null);
  RUN_TEST (test_terminal_setup_size_invalid_fd);
  RUN_TEST (test_terminal_setup_size_pty);
  RUN_TEST (test_set_raw_invalid_fd);
  RUN_TEST (test_set_raw_pty);
  RUN_TEST (test_set_raw_no_status);
  RUN_TEST (test_new_terminal);
  return 0;
}
