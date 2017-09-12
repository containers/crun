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
  int force;
};

static struct list_options_s list_options;

static struct argp_option options[] =
  {
    {"force", 'f', 0, 0, "list the container even if it is still running" },
    { 0 }
  };

static char args_doc[] = "list";

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
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
  int ret;
  struct libcrun_context_s crun_context;
  libcrun_container_list_t *list, *it;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &list_options);

  init_libcrun_context (&crun_context, argv[first_arg], global_args);

  ret = libcrun_get_containers_list (&list, crun_context.state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  printf ("NAME\tPID\tBUNDLE PATH\n");
  for (it = list; it; it = it->next)
    {
      libcrun_container_status_t status;
      ret = libcrun_read_container_status (&status, crun_context.state_root, it->name, err);
      if (UNLIKELY (ret < 0))
        {
          crun_error_write_warning_and_release (stderr, err);
          continue;
        }
      printf ("%s\t%d\t%s\n", it->name, status.pid, status.bundle);

      libcrun_free_container_status (&status);
    }
  libcrun_free_containers_list (list);
  return 0;
}
