/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include <signal.h>

#include "crun.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"
#include "libcrun/sig2str.h"

static char doc[] = "OCI runtime";

enum
  {
    OPTION_CONSOLE_SOCKET = 1000,
    OPTION_PID_FILE,
    OPTION_NO_SUBREAPER,
    OPTION_NO_NEW_KEYRING,
    OPTION_PRESERVE_FDS
  };

struct kill_options_s
{
  int force;
};

static struct kill_options_s kill_options;

static struct argp_option options[] =
  {
    {"force", 'f', 0, 0, "kill the container even if it is still running" },
    { 0 }
  };

static char args_doc[] = "kill CONTAINER [SIGNAL]";

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'f':
      kill_options.force = 1;
      break;

    case ARGP_KEY_NO_ARGS:
      libcrun_fail_with_error (0, "please specify a ID for the container");

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc };

int
crun_command_kill (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg, signal;

  struct libcrun_context_s crun_context;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &kill_options);
  if (argc - first_arg < 1)
    libcrun_fail_with_error (0, "please specify container ID");

  init_libcrun_context (&crun_context, argv[first_arg], global_args);

  signal = SIGTERM;
  if (argc - first_arg > 1)
    {
      int res = str2sig (argv[first_arg + 1], &signal);
      if (UNLIKELY (res < 0))
        libcrun_fail_with_error (0, "unknown signal %s", argv[first_arg + 1]);
    }

  return libcrun_kill_container (&crun_context, argv[first_arg], signal, err);
}
