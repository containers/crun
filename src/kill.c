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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <regex.h>

#include "crun.h"
#include "libcrun/container.h"
#include "libcrun/status.h"
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

struct kill_options_s
{
  bool all;
  bool regex;
};

static struct kill_options_s kill_options;

static struct argp_option options[]
    = { { "all", 'a', 0, 0, "kill all the processes", 0 },
        { "regex", 'r', 0, 0, "the specified CONTAINER is a regular expression (kill multiple containers)", 0 },
        {
            0,
        } };

static char args_doc[] = "kill CONTAINER [SIGNAL]";

static error_t
parse_opt (int key, char *arg arg_unused, struct argp_state *state arg_unused)
{
  switch (key)
    {
    case 'a':
      kill_options.all = true;
      break;

    case 'r':
      kill_options.regex = true;
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
crun_command_kill (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg, signal, ret;

  libcrun_context_t crun_context = {
    0,
  };

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &kill_options);
  crun_assert_n_args (argc - first_arg, 1, 2);

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  signal = SIGTERM;
  if (argc - first_arg > 1)
    {
      signal = libcrun_str2sig (argv[first_arg + 1]);
      if (UNLIKELY (signal < 0))
        libcrun_fail_with_error (0, "unknown signal %s", argv[first_arg + 1]);
    }

  if (kill_options.regex)
    {
      regex_t re;
      libcrun_container_list_t *list, *it;

      ret = regcomp (&re, argv[first_arg], REG_EXTENDED | REG_NOSUB);
      if (UNLIKELY (ret < 0))
        libcrun_fail_with_error (0, "invalid regular expression %s", argv[first_arg]);

      ret = libcrun_get_containers_list (&list, crun_context.state_root, err);
      if (UNLIKELY (ret < 0))
        libcrun_fail_with_error (0, "cannot read containers list");

      for (it = list; it; it = it->next)
        if (regexec (&re, it->name, 0, NULL, 0) == 0)
          {
            ret = libcrun_container_kill (&crun_context, it->name, signal, err);
            if (UNLIKELY (ret < 0))
              libcrun_error_write_warning_and_release (stderr, &err);
          }

      libcrun_free_containers_list (list);
      regfree (&re);
      return 0;
    }

  if (kill_options.all)
    return libcrun_container_kill_all (&crun_context, argv[first_arg], signal, err);

  return libcrun_container_kill (&crun_context, argv[first_arg], signal, err);
}
