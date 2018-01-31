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

static char doc[] = "OCI runtime";

struct exec_options_s
{
  const char *cwd;
  const char *console_socket;
  int tty;
  int detach;
};

enum
  {
    OPTION_CONSOLE_SOCKET = 1000
  };

static struct exec_options_s exec_options;

static struct argp_option options[] =
  {
    {"console-socket", OPTION_CONSOLE_SOCKET, 0, 0, "path to a socket that will receive the master end of the tty" },
    {"tty", 't', 0, 0, "allocate a pseudo-TTY"},
    {"cwd", 'c', "CWD", 0, "current working directory" },
    {"detach", 'd', 0, 0, "detach the command in the background" },
    { 0 }
  };

static char args_doc[] = "exec CONTAINER cmd";

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case OPTION_CONSOLE_SOCKET:
      exec_options.console_socket = arg;
      break;

    case 'd':
      exec_options.detach = 1;
      break;

    case 't':
      exec_options.tty = 1;
      break;

    case 'c':
      exec_options.cwd = arg;
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
crun_command_exec (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int i, first_arg, ret = 0;
  pid_t pid;
  struct libcrun_context_s crun_context;
  oci_container_process *process = NULL;


  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &exec_options);
  if (argc - first_arg < 2)
    libcrun_fail_with_error (0, "please specify at least one argument");

  init_libcrun_context (&crun_context, argv[first_arg], global_args);
  crun_context.detach = exec_options.detach;
  crun_context.console_socket = exec_options.console_socket;

  process = xmalloc (sizeof (*process));
  process->args_len = argc;
  process->args = xmalloc ((argc + 1) * sizeof (*process->args));

  for (i = 0; i < argc; i++)
    process->args[i] = xstrdup (argv[first_arg + i + 1]);
  process->args[i] = NULL;
  if (exec_options.cwd)
    process->cwd = xstrdup (exec_options.cwd);
  process->terminal = exec_options.tty;

  pid = libcrun_exec_container (&crun_context, argv[first_arg], process, err);
  if (UNLIKELY (pid < 0))
    ret = pid;

 exit:
  free_oci_container_process (process);

  return ret;
}
