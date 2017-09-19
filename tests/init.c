/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
 * libocispec is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libocispec is distributed in the hope that it will be useful,
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
#include <error.h>
#include <errno.h>

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
            return 0;
          error (EXIT_FAILURE, errno, "fread");
        }
      s = fwrite (buf, 1, s, stdout);
      if (s == 0)
        error (EXIT_FAILURE, errno, "fwrite");
    }
}

static int
write_to (const char *path, const char *str)
{
  FILE *f = fopen (path, "wb");
  int ret;
  if (f == NULL)
    error (EXIT_FAILURE, errno, "fopen");
  ret = fprintf (f, str);
  if (ret < 0)
    error (EXIT_FAILURE, errno, "fprintf");
  ret = fclose (f);
  if (ret)
    error (EXIT_FAILURE, errno, "fclose");
  return 0;
}

int main (int argc, char **argv)
{
  if (argc < 2)
    error (EXIT_FAILURE, 0, "specify at least one command");

  if (strcmp (argv[1], "cat") == 0)
    {
      if (argc < 3)
        error (EXIT_FAILURE, 0, "'cat' requires an argument");
      return cat (argv[2]);
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
      char buffer[64];
      int ret;

      memset (buffer, 0, sizeof (buffer));
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


  error (EXIT_FAILURE, 0, "unknown command '%s' specified", argv[1]);
  return 0;
}
