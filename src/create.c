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

#include "crun.h"
#include "libcrun/container.h"
#include "libcrun/utils.h"

enum
  {
    OPTION_CONSOLE_SOCKET = 1000,
    OPTION_PID_FILE,
    OPTION_NO_SUBREAPER,
    OPTION_NO_NEW_KEYRING,
    OPTION_PRESERVE_FDS
  };

static const char *bundle = NULL;

static struct libcrun_context_s crun_context;

static struct argp_option options[] =
  {
    {"bundle", 'b', 0, 0, "container bundle (default \".\")" },
    {"console-socket", OPTION_CONSOLE_SOCKET, "SOCKET", 0, "path to a socket that will receive the master end of the tty" },
    {"preserve-fds", OPTION_PRESERVE_FDS, 0, 0, "pass additional FDs to the container"},
    {"pid-file", OPTION_PID_FILE, "FILE", 0, "where to write the PID of the container"},
    {"no-subreaper", OPTION_NO_SUBREAPER, 0, 0, "do not create a subreaper process"},
    {"no-new-keyring", OPTION_NO_NEW_KEYRING, 0, 0, "keep the same session key"},
    { 0 }
  };

static char doc[] = "OCI runtime";

static char args_doc[] = "create [OPTION]... CONTAINER";

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'b':
      bundle = crun_context.bundle = argp_mandatory_argument (arg, state);
      break;

    case OPTION_CONSOLE_SOCKET:
      crun_context.console_socket = argp_mandatory_argument (arg, state);
      break;

    case OPTION_PRESERVE_FDS:
      crun_context.preserve_fds = strtoul (argp_mandatory_argument (arg, state), NULL, 10);
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
      libcrun_fail_with_error (0, "please specify a ID for the container");

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc };

int
crun_command_create (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg;
  libcrun_container *container;

  crun_context.preserve_fds = 0;
  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &crun_context);

  crun_assert_n_args (argc - first_arg, 1, 1);

  if (bundle != NULL)
    if (chdir (bundle) < 0)
      libcrun_fail_with_error (errno, "chdir '%s' failed", bundle);

  container = libcrun_container_load ("config.json", err);
  if (container == NULL)
    libcrun_fail_with_error (0, "error loading config.json");

  init_libcrun_context (&crun_context, argv[first_arg], global_args);
  crun_context.bundle = bundle ? bundle : ".";
  if (getenv ("LISTEN_FDS"))
    crun_context.preserve_fds += strtoll (getenv ("LISTEN_FDS"), NULL, 10);

  return libcrun_container_create (&crun_context, container, err);
}
