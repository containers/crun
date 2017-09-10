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
#include <error.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "crun.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"

static char doc[] = "OCI runtime";

enum
  {
    OPTION_CONSOLE_SOCKET = 1000,
    OPTION_PID_FILE,
    OPTION_NO_SUBREAPER,
    OPTION_NO_NEW_KEYRING,
    OPTION_PRESERVE_FDS
  };

static char *bundle = NULL;

static struct libcrun_context_s crun_context;

static struct argp_option options[] =
  {
    {"bundle", 'b', 0, 0, "container bundle (default \".\")" },
    {"detach", 'd', 0, 0, "detach from the parent" },
    {"console-socket", OPTION_CONSOLE_SOCKET, 0, 0, "path to a socket that will receive the master end of the tty" },
    {"preserve-fds", OPTION_PRESERVE_FDS, 0, 0, "pass additional FDs to the container"},
    {"pid-file", OPTION_PID_FILE, "FILE", 0, "where to write the PID of the container"},
    {"no-subreaper", OPTION_NO_SUBREAPER, 0, 0, "do not create a subreaper process"},
    {"no-new-keyring", OPTION_NO_NEW_KEYRING, 0, 0, "keep the same session key"},
    { 0 }
  };

static char args_doc[] = "run [OPTION]... CONTAINER";

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'd':
      crun_context.detach = 1;
      break;

    case 'b':
      bundle = argp_mandatory_argument (arg, state);
      break;

    case OPTION_CONSOLE_SOCKET:
      crun_context.console_socket = argp_mandatory_argument (arg, state);
      break;

    case OPTION_PRESERVE_FDS:
      crun_context.preserve_fds = atoi (argp_mandatory_argument (arg, state));
      break;

    case OPTION_NO_SUBREAPER:
      crun_context.no_subreaper = 1;
      break;

    case OPTION_NO_NEW_KEYRING:
      crun_context.no_new_keyring = 1;
      break;

    case OPTION_PID_FILE:
      crun_context.pid_file = argp_mandatory_argument (arg, state);
      break;

    case ARGP_KEY_NO_ARGS:
      error (EXIT_FAILURE, 0, "please specify a ID for the container");

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc };

int
crun_command_run (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg;
  libcrun_container *container;

  crun_context.state_root = global_args->root;
  crun_context.systemd_cgroup = global_args->option_systemd_cgroup;
  crun_context.notify_socket = getenv ("NOTIFY_SOCKET");
  crun_context.stderr = stderr;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &crun_context);

  if (bundle != NULL)
    if (chdir (bundle) < 0)
      error (EXIT_FAILURE, errno, "chdir '%s' failed", bundle);
    
  container = libcrun_container_load ("config.json", err);
  if (container == NULL)
    error (EXIT_FAILURE, 0, "error loading config.json");

  crun_context.id = argv[first_arg];
  return libcrun_container_run (container, &crun_context, err);
}
