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
#include "libcrun/container.h"
#include "libcrun/utils.h"
#include "libcrun/cgroup.h"
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

struct ps_options_s
{
  int format;
};

enum
  {
   PS_TABLE = 100,
   PS_JSON,
  };

static struct ps_options_s ps_options;

static struct argp_option options[] =
  {
   {"format", 'f', "FORMAT", 0, "select the output format", 0},
   { 0, }
  };

static char args_doc[] = "ps";

static error_t
parse_opt (int key, char *arg, struct argp_state *state arg_unused)
{
  switch (key)
    {
    case 'f':
      if (strcmp (arg, "table") == 0)
        ps_options.format = PS_TABLE;
      else if (strcmp (arg, "json") == 0)
        ps_options.format = PS_JSON;
      else
        error (EXIT_FAILURE, 0, "invalid format `%s`", arg);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

int
crun_command_ps (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg;
  int ret;
  libcrun_context_t crun_context = {0, };
  libcrun_container_status_t status;
  cleanup_free pid_t *pids = NULL;
  size_t i;

  ps_options.format = PS_TABLE;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &ps_options);
  crun_assert_n_args (argc - first_arg, 1, 1);

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_read_container_status (&status, crun_context.state_root, argv[first_arg], err);
  if (UNLIKELY (ret < 0))
    {
      crun_error_write_warning_and_release (stderr, &err);
      return ret;
    }

  if (status.cgroup_path == NULL || status.cgroup_path[0] == '\0')
    error (EXIT_FAILURE, 0, "the container is not using cgroups");

  ret = libcrun_cgroup_read_pids (status.cgroup_path, true, &pids, err);
  if (UNLIKELY (ret < 0))
    {
      crun_error_write_warning_and_release (stderr, &err);
      return ret;
    }

  switch (ps_options.format)
    {
    case PS_JSON:
      printf ("[\n");
      for (i = 0; pids[i]; i++)
        printf ("  %d%s\n", pids[i], pids[i + 1] ? "," : "");
      printf ("]\n");
      break;

    case PS_TABLE:
      printf ("PID\n");
      for (i = 0; pids[i]; i++)
        printf ("%d\n", pids[i]);
      break;
    }


  return 0;
}
