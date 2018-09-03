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
  const char *process;
  const char *console_socket;
  const char *pid_file;
  char *cwd;
  char **env;
  size_t env_size;
  bool tty;
  bool detach;
};

enum
  {
    OPTION_CONSOLE_SOCKET = 1000,
    OPTION_PID_FILE
  };

static struct exec_options_s exec_options;

static struct argp_option options[] =
  {
    {"console-socket", OPTION_CONSOLE_SOCKET, "SOCKET", 0, "path to a socket that will receive the master end of the tty" },
    {"tty", 't', 0, 0, "allocate a pseudo-TTY"},
    {"process", 'p', "FILE", 0, "path to the process.json"},
    {"cwd", 'c', "CWD", 0, "current working directory" },
    {"detach", 'd', 0, 0, "detach the command in the background" },
    {"env", 'e', "ENV", 0, "add an environment variable" },
    {"pid-file", OPTION_PID_FILE, "FILE", 0, "where to write the PID of the container"},
    { 0 }
  };

static char args_doc[] = "exec CONTAINER cmd";

static void
append_env (const char *arg)
{
  exec_options.env = realloc (exec_options.env, exec_options.env_size + 2);
  if (exec_options.env == NULL)
    error (EXIT_FAILURE, errno, "cannot allocate memory");
  exec_options.env[exec_options.env_size + 1] = NULL;
  exec_options.env[exec_options.env_size] = xstrdup (arg);
  exec_options.env_size++;
}

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case OPTION_CONSOLE_SOCKET:
      exec_options.console_socket = arg;
      break;

    case OPTION_PID_FILE:
      exec_options.pid_file = arg;
      break;

    case 'd':
      exec_options.detach = true;
      break;

    case 'p':
      exec_options.process = arg;
      break;

    case 't':
      exec_options.tty = true;
      break;

    case 'e':
      append_env (arg);
      break;

    case 'c':
      exec_options.cwd = xstrdup (arg);
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
  struct libcrun_context_s crun_context = {0, };

  crun_context.preserve_fds = 0;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &exec_options);
  crun_assert_n_args (argc - first_arg, 2, -1);

  init_libcrun_context (&crun_context, argv[first_arg], global_args);
  crun_context.detach = exec_options.detach;
  crun_context.console_socket = exec_options.console_socket;
  crun_context.pid_file = exec_options.pid_file;

  if (getenv ("LISTEN_FDS"))
    crun_context.preserve_fds += strtoll (getenv ("LISTEN_FDS"), NULL, 10);

  if (exec_options.process)
    return libcrun_container_exec_process_file (&crun_context, argv[first_arg], exec_options.process, err);
  else
    {
      oci_container_process *process = xmalloc (sizeof (*process));
      memset (process, 0, sizeof (*process));

      process->args_len = argc;
      process->args = xmalloc ((argc + 1) * sizeof (*process->args));
      for (i = 0; i < argc - first_arg; i++)
        process->args[i] = xstrdup (argv[first_arg + i + 1]);
      process->args[i] = NULL;
      if (exec_options.cwd)
        process->cwd = exec_options.cwd;
      process->terminal = exec_options.tty;
      process->env = exec_options.env;
      process->env_len = exec_options.env_size;
      process->no_new_privileges = 1;
      ret = libcrun_container_exec (&crun_context, argv[first_arg], process, err);
      free_oci_container_process (process);
      return ret;
    }
}
