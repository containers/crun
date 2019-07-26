/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "crun.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"
#include "libcrun/status.h"

static char doc[] = "OCI runtime";

enum
  {
    OPTION_CONSOLE_SOCKET = 1000,
    OPTION_PID_FILE,
    OPTION_NO_SUBREAPER,
    OPTION_NO_NEW_KEYRING,
    OPTION_PRESERVE_FDS
  };

struct list_options_s
{
};

static struct list_options_s list_options;

static bool quiet;

static struct argp_option options[] =
  {
    {"quiet", 'q', 0, 0, "show only IDs"},
    { 0 }
  };

static char args_doc[] = "list";

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'q':
      quiet = true;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc };

int
crun_command_list (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg;
  int ret, max_length = 4;
  libcrun_context_t crun_context = {0, };
  libcrun_container_list_t *list, *it;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &list_options);
  crun_assert_n_args (argc - first_arg, 0, 0);

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_get_containers_list (&list, crun_context.state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  for (it = list; it; it = it->next)
    {
      int l = strlen (it->name);
      if (l > max_length)
        max_length = l;
    }

  max_length++;

  if (!quiet)
    printf ("%-*s%-10s%-8s %-39s\n", max_length, "NAME", "PID", "STATUS", "BUNDLE PATH");
  for (it = list; it; it = it->next)
    {
      libcrun_container_status_t status;

      ret = libcrun_read_container_status (&status, crun_context.state_root, it->name, err);
      if (UNLIKELY (ret < 0))
        {
          crun_error_write_warning_and_release (stderr, &err);
          continue;
        }
      if (quiet)
        printf ("%s\n", it->name);
      else
        {
          int running = 0;
          int pid = status.pid;
          const char *container_status = NULL;

          ret = libcrun_get_container_state_string (it->name, &status, crun_context.state_root, &container_status, &running, err);
          if (UNLIKELY (ret < 0))
            {
              crun_error_write_warning_and_release (stderr, &err);
              continue;
            }

          if (! running)
            pid = 0;

          printf ("%-*s%-10d%-8s %-39s\n", max_length, it->name, pid, container_status, status.bundle);
        }

      libcrun_free_container_status (&status);
    }
  libcrun_free_containers_list (list);
  return 0;
}
