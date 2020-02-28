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
#include <regex.h>

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

struct delete_options_s
{
  int regex;
  bool force;
};

static struct delete_options_s delete_options;

static struct argp_option options[] =
  {
   {"force", 'f', 0, 0, "delete the container even if it is still running", 0},
   {"regex", 'r', 0, 0, "the specified CONTAINER is a regular expression (delete multiple containers)", 0},
   { 0, }
  };

static char args_doc[] = "delete CONTAINER";

static error_t
parse_opt (int key, char *arg arg_unused, struct argp_state *state arg_unused)
{
  switch (key)
    {
    case 'f':
      delete_options.force = true;
      break;

    case 'r':
      delete_options.regex = true;
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
crun_command_delete (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg, ret;

  libcrun_context_t crun_context = {0, };

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &delete_options);
  crun_assert_n_args (argc - first_arg, 1, 1);

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (delete_options.regex)
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
            ret = libcrun_container_delete (&crun_context, NULL, it->name, delete_options.force, err);
            if (UNLIKELY (ret < 0))
              crun_error_write_warning_and_release (stderr, &err);
          }

      libcrun_free_containers_list (list);
      regfree (&re);
      return 0;
    }

  return libcrun_container_delete (&crun_context, NULL, argv[first_arg], delete_options.force, err);
}
