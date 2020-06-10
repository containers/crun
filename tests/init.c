/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifdef HAVE_ERROR_H
# include <error.h>
#else
# define error(status, errno, fmt, ...) do {                            \
    if (errno == 0)                                                     \
      fprintf (stderr, "crun: " fmt "\n", ##__VA_ARGS__);               \
    else                                                                \
      {                                                                 \
        fprintf (stderr, "crun: " fmt, ##__VA_ARGS__);                  \
        fprintf (stderr, ": %s\n", strerror (errno));                   \
      }                                                                 \
    if (status)                                                         \
      exit (status);                                                    \
  } while(0)
#endif

static int
cat (char *file)
{
  FILE *f = fopen (file, "rb");
  char buf[512];
  if (f == NULL)
    error (EXIT_FAILURE, errno, "fopen");
  while (1)
    {
      size_t s = fread (buf, 1, sizeof (buf), f);
      if (s == 0)
        {
          if (feof (f))
            {
              fclose (f);
              return 0;
            }
          fclose (f);
          error (EXIT_FAILURE, errno, "fread");
        }
      s = fwrite (buf, 1, s, stdout);
      if (s == 0)
        error (EXIT_FAILURE, errno, "fwrite");
    }
}

static int
open_only (char *file)
{
  int fd = open (file, O_RDONLY);
  if (fd >= 0)
    {
      close (fd);
      exit (0);
    }
  error (EXIT_FAILURE, errno, "could not open %s", file);
  return -1;
}

static int
write_to (const char *path, const char *str)
{
  FILE *f = fopen (path, "wb");
  int ret;
  if (f == NULL)
    error (EXIT_FAILURE, errno, "fopen");
  ret = fprintf (f, "%s", str);
  if (ret < 0)
    error (EXIT_FAILURE, errno, "fprintf");
  ret = fclose (f);
  if (ret)
    error (EXIT_FAILURE, errno, "fclose");
  return 0;
}

static int
ls (char *path)
{
  DIR *dir = opendir (path);
  if (dir == NULL)
    error (EXIT_FAILURE, errno, "opendir");

  for (;;)
    {
      struct dirent *de;
      errno = 0;
      de = readdir (dir);
      if (de == NULL && errno)
        error (EXIT_FAILURE, errno, "readdir");
      if (de == NULL)
        {
          closedir (dir);
          return 0;
        }
      printf ("%s\n", de->d_name);
    }
  closedir (dir);
  return 0;
}

int main (int argc, char **argv)
{
  if (argc < 2)
    error (EXIT_FAILURE, 0, "specify at least one command");

  if (strcmp (argv[1], "true") == 0)
    {
      exit (0);
    }

  if (strcmp (argv[1], "echo") == 0)
    {
      if (argc < 3)
        error (EXIT_FAILURE, 0, "'cat' requires an argument");
      fputs (argv[2], stdout);
      exit (0);
    }

  if (strcmp (argv[1], "cat") == 0)
    {
      if (argc < 3)
        error (EXIT_FAILURE, 0, "'cat' requires an argument");
      return cat (argv[2]);
    }

  if (strcmp (argv[1], "open") == 0)
    {
      if (argc < 3)
        error (EXIT_FAILURE, 0, "'open' requires an argument");
      return open_only (argv[2]);
    }

  if (strcmp (argv[1], "cwd") == 0)
    {
      int ret;
      char *wd = get_current_dir_name ();
      if (wd == NULL)
        error (EXIT_FAILURE, 0, "OOM");

      ret = printf ("%s\n", wd);
      if (ret < 0)
        error (EXIT_FAILURE, errno, "printf");
      return 0;
    }

  if (strcmp (argv[1], "gethostname") == 0)
    {
      char buffer[64] = {};
      int ret;

      ret = gethostname (buffer, sizeof (buffer) - 1);
      if (ret < 0)
        error (EXIT_FAILURE, errno, "gethostname");

      ret = printf ("%s\n", buffer);
      if (ret < 0)
        error (EXIT_FAILURE, errno, "printf");
      return 0;
    }

  if (strcmp (argv[1], "isatty") == 0)
    {
      int fd;
      if (argc < 3)
        error (EXIT_FAILURE, 0, "'isatty' requires two arguments");
      fd = atoi (argv[2]);
      printf (isatty (fd) ? "true" : "false");
      return 0;
    }

  if (strcmp (argv[1], "write") == 0)
    {
      if (argc < 3)
        error (EXIT_FAILURE, 0, "'write' requires two arguments");
      return write_to (argv[2], argv[3]);
    }
  if (strcmp (argv[1], "pause") == 0)
    {
      close (1);
      close (2);
      pause ();
      exit (0);
    }
  if (strcmp (argv[1], "forkbomb") == 0)
    {
      int i, n;
      if (argc < 3)
        error (EXIT_FAILURE, 0, "'forkbomb' requires two arguments");
      n = atoi (argv[2]);
      if (n < 0)
        return 0;
      for (i = 0; i < n; i++)
        {
          pid_t pid = fork ();
          if (pid < 0)
            error (EXIT_FAILURE, errno, "fork");
          if (pid == 0)
            sleep (100);
        }

      return 0;
    }

  if (strcmp (argv[1], "ls") == 0)
    {
      /* Fork so that ls /proc/1/fd doesn't show more fd's.  */
      pid_t pid;
      if (argc < 3)
        error (EXIT_FAILURE, 0, "'ls' requires two arguments");
      pid = fork ();
      if (pid < 0)
        error (EXIT_FAILURE, errno, "fork");
      if (pid)
        {
          int ret, status;
          do
            ret = waitpid (pid, &status, 0);
          while (ret < 0 && errno == EINTR);
          if (ret < 0)
            return ret;
          return status;
        }
      return ls (argv[2]);
    }


  error (EXIT_FAILURE, 0, "unknown command '%s' specified", argv[1]);
  return 0;
}
