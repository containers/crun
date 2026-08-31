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

#include "crun.h"

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
  bool quiet;
  int format;
};

enum
{
  LIST_TABLE = 100,
  LIST_JSON,
};

static struct list_options_s list_options;

static struct argp_option options[]
    = { { "quiet", 'q', 0, 0, "show only IDs", 0 },
        { "format", 'f', "FORMAT", 0, "select one of: table or json (default: \"table\")", 0 },
        {
            0,
        } };

static char args_doc[] = "list";

static error_t
parse_opt (int key, char *arg, struct argp_state *state arg_unused)
{
  switch (key)
    {
    case 'q':
      list_options.quiet = true;
      break;
    case 'f':
      if (strcmp (arg, "table") == 0)
        list_options.format = LIST_TABLE;
      else if (strcmp (arg, "json") == 0)
        list_options.format = LIST_JSON;
      else
        libcrun_fail_with_error (0, "invalid format `%s`", arg);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

int
crun_command_list (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg;
  int ret, max_length = 4;
  cleanup_context libcrun_context_t *crun_context = NULL;
  libcrun_container_list_t *list = NULL;
  libcrun_container_iter_t *it;
  const char *name;

  list_options.format = LIST_TABLE;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &list_options);
  crun_assert_n_args (argc - first_arg, 0, 0);

  crun_context = new_libcrun_context (global_args);

  ret = init_libcrun_context (crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (list_options.format == LIST_JSON)
    {
      cleanup_free char *json = NULL;

      ret = libcrun_container_list_json (crun_context, &json, err);
      if (UNLIKELY (ret < 0))
        return ret;

      fputs (json, stdout);
      return 0;
    }

  ret = libcrun_container_list (crun_context, &list, err);
  if (UNLIKELY (ret < 0))
    return ret;

  for (it = libcrun_container_list_iter (list); libcrun_container_iter_next (it, &name);)
    {
      int l = strlen (name);
      if (l > max_length)
        max_length = l;
    }
  libcrun_container_iter_free (it);

  max_length++;

  if (! list_options.quiet)
    printf ("%-*s%-10s%-8s %-39s %-30s %s\n", max_length, "NAME", "PID", "STATUS", "BUNDLE PATH", "CREATED", "OWNER");

  for (it = libcrun_container_list_iter (list); libcrun_container_iter_next (it, &name);)
    {
      libcrun_status_t *status = NULL;

      ret = libcrun_container_status_load (crun_context, name, &status, err);
      if (UNLIKELY (ret < 0))
        {
          libcrun_error_report_and_release (err);
          continue;
        }
      if (list_options.quiet)
        printf ("%s\n", name);
      else
        {
          int running = 0;
          int pid = libcrun_status_get_pid (status);
          const char *container_status = NULL;

          ret = libcrun_container_get_state_string (crun_context, name, &container_status, &running, err);
          if (UNLIKELY (ret < 0))
            {
              libcrun_error_report_and_release (err);
              libcrun_container_status_free (status);
              continue;
            }

          if (! running)
            pid = 0;

          printf ("%-*s%-10d%-8s %-39s %-30s %s\n", max_length, name, pid, container_status,
                  libcrun_status_get_bundle (status), libcrun_status_get_created (status),
                  libcrun_status_get_owner (status));
        }

      libcrun_container_status_free (status);
    }
  libcrun_container_iter_free (it);

  libcrun_container_list_free (list);
  return ret >= 0 ? 0 : ret;
}
