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
#include <stdlib.h>
#include <error.h>
#include <argp.h>
#include <string.h>

#include "crun.h"
#include "libcrun/utils.h"

/* Commands.  */
#include "run.h"
#include "delete.h"
#include "kill.h"
#include "list.h"

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
  con->stderr = stderr;
}

static int
crun_command_not_implemented (struct crun_global_arguments *global_args, int argc, char **arg, libcrun_error_t *error)
{
  return crun_make_error (error, 0, "sadly, this wasn't implemented yet");
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
    COMMAND_STATE
  };

struct commands_s commands[] =
  {
    { COMMAND_CREATE, "create", crun_command_not_implemented},
    { COMMAND_DELETE, "delete", crun_command_delete},
    { COMMAND_EXEC, "exec", crun_command_not_implemented},
    { COMMAND_LIST, "list", crun_command_list},
    { COMMAND_KILL, "kill", crun_command_kill},
    { COMMAND_RUN, "run", crun_command_run},
    { COMMAND_SPEC, "spec", crun_command_not_implemented},
    { COMMAND_START, "start", crun_command_not_implemented},
    { COMMAND_STATE, "state", crun_command_not_implemented},
    { 0, 0}
  };

static char doc[] =                                                  \
  "\nCOMMANDS:\n"                                                    \
  "\tcreate - create a container\n"                                  \
  "\tdelete - remove definition for a container\n"                   \
  "\texec   - exec a command in a running container\n"               \
  "\tlist   - list known containers\n"                               \
  "\tkill   - send a signal to the container init process\n"         \
  "\trun    - run a container\n"                                     \
  "\tspec   - generate a configuration file\n"                       \
  "\tstart  - start a container\n"                                   \
  "\tstate  - output the state of a container\n"                     \
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
    OPTION_ROOT
  };
  

const char *argp_program_version = PACKAGE_STRING;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static struct argp_option options[] =
  {
    {"debug", OPTION_DEBUG, 0, 0, "produce verbose output" },
    {"systemd-cgroup", OPTION_SYSTEMD_CGROUP, 0, 0,"use systemd cgroups" },
    {"log", OPTION_LOG, 0, 0, "log file" },
    {"root", OPTION_ROOT, "DIR",  0},
    { 0 }
  };

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case OPTION_DEBUG:
      arguments.debug = 1;
      break;

    case OPTION_SYSTEMD_CGROUP:
      arguments.option_systemd_cgroup = 1;
      break;

    case OPTION_LOG:
      arguments.log = argp_mandatory_argument (arg, state);
      break;

    case OPTION_ROOT:
      arguments.root = argp_mandatory_argument (arg, state);
      break;

    case ARGP_KEY_NO_ARGS:
      error (EXIT_FAILURE, 0, "please specify a command");

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int
main (int argc, char **argv)
{
  libcrun_error_t err = NULL;
  struct commands_s *command;
  int ret, first_argument;

  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, &first_argument, &arguments);

  command = get_command (argv[first_argument]);
  if (command == NULL)
    error (EXIT_FAILURE, 0, "unknown command %s", argv[first_argument]);

  ret = command->handler (&arguments, argc - first_argument, argv + first_argument, &err);
  if (ret && err)
    error (EXIT_FAILURE, err->status, "%s", err->msg);
  return ret;
}
