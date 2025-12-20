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
#include <git-version.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <limits.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#include "crun.h"
#include "libcrun/utils.h"
#include "libcrun/custom-handler.h"
#include "libcrun/status.h"

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
#include "oci_features.h"
#include "ps.h"
#include "checkpoint.h"
#include "mounts.h"
#include "restore.h"

static struct crun_global_arguments arguments;

static struct custom_handler_manager_s *handler_manager;

static struct custom_handler_manager_s *
libcrun_get_handler_manager ()
{
  if (handler_manager == NULL)
    {
      cleanup_free char *handlers_path = NULL;
      libcrun_error_t err;
      int ret;

      handler_manager = libcrun_handler_manager_create (&err);
      if (UNLIKELY (handler_manager == NULL))
        libcrun_fail_with_error (err->status, "%s", err->msg);

      handlers_path = strdup (CRUN_LIBDIR "/handlers");
      if (UNLIKELY (handlers_path == NULL))
        OOM ();

      if (access (handlers_path, F_OK) == 0)
        {
          ret = libcrun_handler_manager_load_directory (handler_manager, handlers_path, &err);
          if (UNLIKELY (ret < 0))
            libcrun_fail_with_error (err->status, "%s", err->msg);
        }
    }
  return handler_manager;
}

struct commands_s
{
  int value;
  const char *name;
  int (*handler) (struct crun_global_arguments *, int, char **, libcrun_error_t *);
};

int
init_libcrun_context (libcrun_context_t *con, const char *id, struct crun_global_arguments *glob, libcrun_error_t *err)
{
  int ret;

  con->id = id;
  con->state_root = glob->root;
  con->systemd_cgroup = glob->option_systemd_cgroup;
  con->force_no_cgroup = glob->option_force_no_cgroup;
  con->notify_socket = getenv ("NOTIFY_SOCKET");
  con->fifo_exec_wait_fd = -1;
  con->argc = glob->argc;
  con->argv = glob->argv;

  /* Check if global handler is configured and pass it down to crun context */
  con->handler = glob->handler;

  ret = libcrun_init_logging (&con->output_handler, &con->output_handler_arg, id, glob->log, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (glob->log_format)
    {
      ret = libcrun_set_log_format (glob->log_format, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  libcrun_set_verbosity (glob->verbosity);
  libcrun_debug ("Using debug verbosity");

  if (con->bundle == NULL)
    con->bundle = ".";

  con->handler_manager = libcrun_get_handler_manager ();

  return 0;
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
  COMMAND_FEATURES,
  COMMAND_PS,
  COMMAND_CHECKPOINT,
  COMMAND_RESTORE,
  COMMAND_MOUNTS,
};

struct commands_s commands[] = { { COMMAND_CREATE, "create", crun_command_create },
                                 { COMMAND_DELETE, "delete", crun_command_delete },
                                 { COMMAND_EXEC, "exec", crun_command_exec },
                                 { COMMAND_LIST, "list", crun_command_list },
                                 { COMMAND_KILL, "kill", crun_command_kill },
                                 { COMMAND_PS, "ps", crun_command_ps },
                                 { COMMAND_RUN, "run", crun_command_run },
                                 { COMMAND_SPEC, "spec", crun_command_spec },
                                 { COMMAND_START, "start", crun_command_start },
                                 { COMMAND_STATE, "state", crun_command_state },
                                 { COMMAND_UPDATE, "update", crun_command_update },
                                 { COMMAND_PAUSE, "pause", crun_command_pause },
                                 { COMMAND_UNPAUSE, "resume", crun_command_unpause },
                                 { COMMAND_FEATURES, "features", crun_command_features },
#if HAVE_CRIU && HAVE_DLOPEN
                                 { COMMAND_CHECKPOINT, "checkpoint", crun_command_checkpoint },
                                 { COMMAND_RESTORE, "restore", crun_command_restore },
#endif
                                 { COMMAND_MOUNTS, "mounts", crun_command_mounts },
                                 {
                                     0,
                                 } };

static char doc[] = "\nCOMMANDS:\n"
#if HAVE_CRIU && HAVE_DLOPEN
                    "\tcheckpoint  - checkpoint a container\n"
#endif
                    "\tcreate      - create a container\n"
                    "\tdelete      - remove definition for a container\n"
                    "\texec        - exec a command in a running container\n"
                    "\tfeatures    - show the enabled features\n"
                    "\tlist        - list known containers\n"
                    "\tmounts      - add or remove mounts from a running container\n"
                    "\tkill        - send a signal to the container init process\n"
                    "\tps          - show the processes in the container\n"
#if HAVE_CRIU && HAVE_DLOPEN
                    "\trestore     - restore a container\n"
#endif
                    "\trun         - run a container\n"
                    "\tspec        - generate a configuration file\n"
                    "\tstart       - start a container\n"
                    "\tstate       - output the state of a container\n"
                    "\tpause       - pause all the processes in the container\n"
                    "\tresume      - unpause the processes in the container\n"
                    "\tupdate      - update container resource constraints\n";

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
  OPTION_VERSION = 'v',
  OPTION_VERSION_CAP = 'V',
  OPTION_DEBUG = 1000,
  OPTION_SYSTEMD_CGROUP,
  OPTION_CGROUP_MANAGER,
  OPTION_LOG,
  OPTION_LOG_FORMAT,
  OPTION_LOG_LEVEL,
  OPTION_ROOT,
  OPTION_ROOTLESS
};

const char *argp_program_bug_address = "https://github.com/containers/crun/issues";

static struct argp_option options[] = { { "debug", OPTION_DEBUG, 0, 0, "produce verbose output, similar to --log-level=debug", 0 },
                                        { "cgroup-manager", OPTION_CGROUP_MANAGER, "MANAGER", 0, "cgroup manager", 0 },
                                        { "systemd-cgroup", OPTION_SYSTEMD_CGROUP, 0, 0, "use systemd cgroups", 0 },
                                        { "log", OPTION_LOG, "FILE", 0, "log destination: '[file:]PATH', 'journald:ID' or 'syslog:ID' (defaults to stderr)", 0 },
                                        { "log-format", OPTION_LOG_FORMAT, "FORMAT", 0, "log format: 'text' (default) or 'json'", 0 },
                                        { "log-level", OPTION_LOG_LEVEL, "LEVEL", 0, "log level to use: 'error' (default), 'warning' or 'debug'", 0 },
                                        { "root", OPTION_ROOT, "DIR", 0, NULL, 0 },
                                        { "rootless", OPTION_ROOTLESS, "VALUE", 0, NULL, 0 },
                                        { "version", OPTION_VERSION, 0, 0, NULL, 0 },
                                        // alias OPTION_VERSION_CAP with OPTION_VERSION
                                        { NULL, OPTION_VERSION_CAP, 0, OPTION_ALIAS, NULL, 0 },
                                        {
                                            0,
                                        } };

static void
print_version (FILE *stream, struct argp_state *state arg_unused)
{
  libcrun_error_t err = NULL;
  cleanup_free char *rundir = NULL;
  int ret;

  fprintf (stream, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
  fprintf (stream, "commit: %s\n", GIT_VERSION);

  ret = libcrun_get_state_directory (&rundir, arguments.root, NULL, &err);
  if (LIKELY (ret == 0))
    fprintf (stream, "rundir: %s\n", rundir);
  else
    libcrun_error_release (&err);

  fprintf (stream, "spec: 1.0.0\n");

#ifdef HAVE_SYSTEMD
  fprintf (stream, "+SYSTEMD ");
#endif
  fprintf (stream, "+SELINUX ");
  fprintf (stream, "+APPARMOR ");
#ifdef HAVE_CAP
  fprintf (stream, "+CAP ");
#endif
#ifdef HAVE_SECCOMP
  fprintf (stream, "+SECCOMP ");
#endif
#ifdef HAVE_EBPF
  fprintf (stream, "+EBPF ");
#endif
#if HAVE_CRIU && HAVE_DLOPEN
  fprintf (stream, "+CRIU ");
#endif

  libcrun_handler_manager_print_feature_tags (libcrun_get_handler_manager (), stream);

  fprintf (stream, "+YAJL\n");
}

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  const char *tmp;

  switch (key)
    {
    case OPTION_DEBUG:
      arguments.verbosity = LIBCRUN_VERBOSITY_DEBUG;
      break;

    case OPTION_CGROUP_MANAGER:
      tmp = argp_mandatory_argument (arg, state);
      if (strcmp (tmp, "systemd") == 0)
        {
          arguments.option_force_no_cgroup = false;
          arguments.option_systemd_cgroup = true;
        }
      else if (strcmp (tmp, "cgroupfs") == 0)
        {
          arguments.option_force_no_cgroup = false;
          arguments.option_systemd_cgroup = false;
        }
      else if (strcmp (tmp, "disabled") == 0)
        {
          arguments.option_systemd_cgroup = false;
          arguments.option_force_no_cgroup = true;
        }
      else
        {
          libcrun_fail_with_error (0, "unknown cgroup manager specified");
        }
      break;

    case OPTION_SYSTEMD_CGROUP:
      arguments.option_force_no_cgroup = false;
      arguments.option_systemd_cgroup = true;
      break;

    case OPTION_LOG:
      arguments.log = argp_mandatory_argument (arg, state);
      break;

    case OPTION_LOG_FORMAT:
      arguments.log_format = argp_mandatory_argument (arg, state);
      break;

    case OPTION_LOG_LEVEL:
      tmp = argp_mandatory_argument (arg, state);
      if (strcmp (tmp, "error") == 0)
        {
          arguments.verbosity = LIBCRUN_VERBOSITY_ERROR;
        }
      else if (strcmp (tmp, "warning") == 0)
        {
          arguments.verbosity = LIBCRUN_VERBOSITY_WARNING;
        }
      else if (strcmp (tmp, "debug") == 0)
        {
          arguments.verbosity = LIBCRUN_VERBOSITY_DEBUG;
        }
      else
        {
          libcrun_fail_with_error (0, "unknown verbosity `%s` specified", arg);
        }
      break;

    case OPTION_ROOT:
      arguments.root = argp_mandatory_argument (arg, state);
      break;

    case OPTION_ROOTLESS:
      /* Ignored.  So that a runc command line won't fail.  */
      break;

    case ARGP_KEY_NO_ARGS:
      libcrun_fail_with_error (0, "please specify a command");

    case OPTION_VERSION:
    case OPTION_VERSION_CAP:
      print_version (stdout, state);
      exit (EXIT_SUCCESS);
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
    error (EXIT_FAILURE, 0, "`%s` requires a minimum of %d arguments", command->name, min);
  if (max >= 0 && n > max)
    error (EXIT_FAILURE, 0, "`%s` requires a maximum of %d arguments", command->name, max);
}

char *
argp_mandatory_argument (char *arg, struct argp_state *state)
{
  if (arg)
    return arg;
  return state->argv[state->next++];
}

int
parse_int_or_fail (const char *str, const char *kind)
{
  char *endptr = NULL;
  long long l;

  errno = 0;
  l = strtoll (str, &endptr, 10);
  if (errno != 0)
    libcrun_fail_with_error (errno, "invalid value for `%s`", kind);
  if (endptr != NULL && *endptr != '\0')
    libcrun_fail_with_error (EINVAL, "invalid value for `%s`", kind);
  if (l < INT_MIN || l > INT_MAX)
    libcrun_fail_with_error (ERANGE, "invalid value for `%s`", kind);

  return (int) l;
}

static struct argp argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

int ensure_cloned_binary (void);

static void
fill_handler_from_argv0 (char *argv0, struct crun_global_arguments *args)
{
  const char *b = basename (argv0);
#ifdef HAVE_LIBKRUN
  if (strcmp (b, "krun") == 0)
    {
      args->handler = "krun";
      return;
    }
#endif
  if (has_prefix (b, "crun-") && b[5] != '\0')
    args->handler = b + 5;
}

static char **
copy_args (char **argv, int argc)
{
  char **buff = xmalloc0 ((argc + 1) * sizeof (char *));
  for (int i = 0; i < argc; i++)
    buff[i] = argv[i];

  return buff;
}

int
main (int argc, char **argv)
{
  libcrun_error_t err = NULL;
  int ret, first_argument = 0;

  arguments.argc = argc;
  arguments.argv = argv;

#ifdef DYNLOAD_LIBCRUN
  if (ensure_cloned_binary () < 0)
    {
      fprintf (stderr, "Failed to re-execute libcrun via memory file descriptor\n");
      _safe_exit (EXIT_FAILURE);
    }
  /* Resolve all libcrun weak dependencies.  */
  if (dlopen ("libcrun.so", RTLD_GLOBAL | RTLD_DEEPBIND | RTLD_LAZY) == NULL)
    error (EXIT_FAILURE, 0, "could not load `libcrun.so`: `%s`", dlerror ());
#endif

  fill_handler_from_argv0 (argv[0], &arguments);
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, &first_argument, &arguments);

  command = get_command (argv[first_argument]);
  if (command == NULL)
    libcrun_fail_with_error (0, "unknown command %s", argv[first_argument]);

  int command_argc = argc - first_argument;
  cleanup_free char **command_argv = copy_args (argv + first_argument, command_argc);
  command_argv[0] = argv[0];

  ret = command->handler (&arguments, command_argc, command_argv, &err);
  if (ret && err)
    libcrun_fail_with_error (err->status, "%s", err->msg);

  return ret;
}
