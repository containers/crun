/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020 Giuseppe Scrivano <giuseppe@scrivano.org>
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
    OPTION_PRESERVE_FDS,
    OPTION_NO_PIVOT
  };

static const char *bundle = NULL;

static libcrun_context_t crun_context;

static struct argp_option options[] =
  {
   {"bundle", 'b', 0, 0, "container bundle (default \".\")", 0},
   {"config", 'f', "FILE", 0, "override the config file name", 0},
   {"console-socket", OPTION_CONSOLE_SOCKET, "SOCK", 0, "path to a socket that will receive the ptmx end of the tty", 0},
   {"preserve-fds", OPTION_PRESERVE_FDS, 0, 0, "pass additional FDs to the container", 0},
   {"no-pivot", OPTION_NO_PIVOT, 0, 0, "do not use pivot_root", 0},
   {"pid-file", OPTION_PID_FILE, "FILE", 0, "where to write the PID of the container", 0},
   {"no-subreaper", OPTION_NO_SUBREAPER, 0, 0, "do not create a subreaper process", 0},
   {"no-new-keyring", OPTION_NO_NEW_KEYRING, 0, 0, "keep the same session key", 0},
   { 0, }
  };

static char doc[] = "OCI runtime";

static char args_doc[] = "create [OPTION]... CONTAINER";

static const char *config_file = "config.json";

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'b':
      bundle = crun_context.bundle = argp_mandatory_argument (arg, state);
      break;

    case 'f':
      config_file = argp_mandatory_argument (arg, state);
      break;

    case OPTION_CONSOLE_SOCKET:
      crun_context.console_socket = argp_mandatory_argument (arg, state);
      break;

    case OPTION_PRESERVE_FDS:
      crun_context.preserve_fds = strtoul (argp_mandatory_argument (arg, state), NULL, 10);
      break;

    case OPTION_NO_SUBREAPER:
      crun_context.no_subreaper = true;
      break;

    case OPTION_NO_PIVOT:
      crun_context.no_pivot = true;
      break;

    case OPTION_NO_NEW_KEYRING:
      crun_context.no_new_keyring = true;
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

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

int
crun_command_create (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg, ret;
  libcrun_container_t *container;
  cleanup_free char *bundle_cleanup = NULL;

  crun_context.preserve_fds = 0;
  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &crun_context);

  crun_assert_n_args (argc - first_arg, 1, 1);

  /* Make sure the bundle is an absolute path.  */
  if (bundle)
    {
      if (bundle[0] != '/')
        {
          bundle_cleanup = realpath (bundle, NULL);
          if (bundle_cleanup == NULL)
            libcrun_fail_with_error (errno, "realpath `%s` failed", bundle);
          bundle = bundle_cleanup;
        }

      if (chdir (bundle) < 0)
        libcrun_fail_with_error (errno, "chdir `%s` failed", bundle);
    }

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  container = libcrun_container_load_from_file (config_file, err);
  if (container == NULL)
    libcrun_fail_with_error (0, "error loading config.json");

  crun_context.bundle = bundle ? bundle : ".";
  if (getenv ("LISTEN_FDS"))
    crun_context.preserve_fds += strtoll (getenv ("LISTEN_FDS"), NULL, 10);

  return libcrun_container_create (&crun_context, container, 0, err);
}
