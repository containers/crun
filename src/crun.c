/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include <stdlib.h>
#include <argp.h>
#include <string.h>

#include "crun.h"
#include "libcrun/utils.h"

/* Commands.  */
#include "run.h"
#include "delete.h"
#include "kill.h"
#include "list.h"
#include "start.h"
#include "create.h"
#include "exec.h"
#include "state.h"
#include "update.h"
#include "spec.h"
#include "pause.h"
#include "unpause.h"

static struct crun_global_arguments arguments;

struct commands_s
{
  int value;
  const char *name;
  int (*handler) (struct crun_global_arguments *, int, char **, libcrun_error_t *);
};

void
init_libcrun_context (struct libcrun_context_s *con, const char *id, struct crun_global_arguments *glob)
{
  con->id = id;
  con->state_root = glob->root;
  con->systemd_cgroup = glob->option_systemd_cgroup;
  con->notify_socket = getenv ("NOTIFY_SOCKET");
  con->fifo_exec_wait_fd = -1;
  if (glob->log == NULL)
    con->errfile = stderr;
  else
    {
      con->errfile = fopen (glob->log, "a+");
      if (con->errfile == NULL)
        libcrun_fail_with_error (errno, "open log file %s\n", glob->log);

      crun_set_output_handler (log_write_to_stream, con->errfile);
    }
  if (con->bundle == NULL)
    con->bundle = ".";
}

enum
  {
    COMMAND_CREATE = 1000,
    COMMAND_DELETE,
    COMMAND_EXEC,
    COMMAND_LIST,
    COMMAND_KILL,
    COMMAND_RUN,
    COMMAND_SPEC,
    COMMAND_START,
    COMMAND_STATE,
    COMMAND_UPDATE,
    COMMAND_PAUSE,
    COMMAND_UNPAUSE,
  };

struct commands_s commands[] =
  {
    { COMMAND_CREATE, "create", crun_command_create},
    { COMMAND_DELETE, "delete", crun_command_delete},
    { COMMAND_EXEC, "exec", crun_command_exec},
    { COMMAND_LIST, "list", crun_command_list},
    { COMMAND_KILL, "kill", crun_command_kill},
    { COMMAND_RUN, "run", crun_command_run},
    { COMMAND_SPEC, "spec", crun_command_spec},
    { COMMAND_START, "start", crun_command_start},
    { COMMAND_STATE, "state", crun_command_state},
    { COMMAND_UPDATE, "update", crun_command_update},
    { COMMAND_PAUSE, "pause", crun_command_pause},
    { COMMAND_UNPAUSE, "resume", crun_command_unpause},
    { 0, 0}
  };

static char doc[] =                                                   \
  "\nCOMMANDS:\n"                                                     \
  "\tcreate  - create a container\n"                                  \
  "\tdelete  - remove definition for a container\n"                   \
  "\texec    - exec a command in a running container\n"               \
  "\tlist    - list known containers\n"                               \
  "\tkill    - send a signal to the container init process\n"         \
  "\trun     - run a container\n"                                     \
  "\tspec    - generate a configuration file\n"                       \
  "\tstart   - start a container\n"                                   \
  "\tstate   - output the state of a container\n"                     \
  "\tpause   - pause all the processes in the container\n"            \
  "\tresume  - unpause the processes in the container\n"              \
  "\tupdate  - update container resource constraints\n"               \
  ;
static char args_doc[] = "COMMAND [OPTION...]";

static struct commands_s *
get_command (const char *arg)
{
  struct commands_s *it;
  for (it = commands; it->value; it++)
    if (strcmp (it->name, arg) == 0)
      return it;
  return NULL;
}

enum
  {
    OPTION_DEBUG = 1000,
    OPTION_SYSTEMD_CGROUP,
    OPTION_LOG,
    OPTION_ROOT,
    OPTION_ROOTLESS
  };


const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static struct argp_option options[] =
  {
    {"debug", OPTION_DEBUG, 0, 0, "produce verbose output"},
    {"systemd-cgroup", OPTION_SYSTEMD_CGROUP, 0, 0, "use systemd cgroups"},
    {"log", OPTION_LOG, "FILE", 0},
    {"root", OPTION_ROOT, "DIR",  0},
    {"rootless", OPTION_ROOT, "VALUE",  0},
    { 0 }
  };

static void
print_version_and_exit ()
{
  printf ("%s\nspec: 1.0.0\n", argp_program_version);
  exit (EXIT_SUCCESS);
}

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case OPTION_DEBUG:
      arguments.debug = true;
      break;

    case OPTION_SYSTEMD_CGROUP:
      arguments.option_systemd_cgroup = true;
      break;

    case OPTION_LOG:
      arguments.log = argp_mandatory_argument (arg, state);
      break;

    case OPTION_ROOT:
      arguments.root = argp_mandatory_argument (arg, state);
      break;

    case OPTION_ROOTLESS:
      /* Ignored.  So that a runc command line won't fail.  */
      break;

    case 'v':
      print_version_and_exit ();
      break;

    case ARGP_KEY_NO_ARGS:
      libcrun_fail_with_error (0, "please specify a command");

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct commands_s *command;

void
crun_assert_n_args (int n, int min, int max)
{
  if (min >= 0 && n < min)
    error (EXIT_FAILURE, 0, "'%s' requires a minimum of %d arguments", command->name, min);
  if (max >= 0 && n > max)
    error (EXIT_FAILURE, 0, "'%s' requires a maximum of %d arguments", command->name, max);
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int
main (int argc, char **argv)
{
  libcrun_error_t err = NULL;
  int ret, first_argument;

  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, &first_argument, &arguments);

  command = get_command (argv[first_argument]);
  if (command == NULL)
    libcrun_fail_with_error (0, "unknown command %s", argv[first_argument]);

  ret = command->handler (&arguments, argc - first_argument, argv + first_argument, &err);
  if (ret && err)
    libcrun_fail_with_error (err->status, "%s", err->msg);
  return ret;
}
