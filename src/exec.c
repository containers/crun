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
#include "libcrun/linux.h"

static char doc[] = "OCI runtime";

struct exec_options_s
{
  bool tty;
  bool detach;
  bool no_new_privs;
  int preserve_fds;
  const char *process;
  const char *console_socket;
  const char *pid_file;
  char *process_label;
  char *apparmor;
  char *cwd;
  char *user;
  char **env;
  char **cap;
  size_t cap_size;
  size_t env_size;
  char *cgroup;
};

enum
{
  OPTION_CONSOLE_SOCKET = 1000,
  OPTION_PID_FILE,
  OPTION_CWD,
  OPTION_PRESERVE_FDS,
  OPTION_NO_NEW_PRIVS,
  OPTION_PROCESS_LABEL,
  OPTION_APPARMOR,
  OPTION_CGROUP,
};

static struct exec_options_s exec_options;

static struct argp_option options[]
    = { { "console-socket", OPTION_CONSOLE_SOCKET, "SOCKET", 0,
          "path to a socket that will receive the ptmx end of the tty", 0 },
        { "tty", 't', "TTY", OPTION_ARG_OPTIONAL, "allocate a pseudo-TTY", 0 },
        { "process", 'p', "FILE", 0, "path to the process.json", 0 },
        { "cwd", OPTION_CWD, "CWD", 0, "current working directory", 0 },
        { "cgroup", OPTION_CGROUP, "PATH", 0, "sub-cgroup in the container", 0 },
        { "detach", 'd', 0, 0, "detach the command in the background", 0 },
        { "user", 'u', "USERSPEC", 0, "specify the user in the form UID[:GID]", 0 },
        { "env", 'e', "ENV", 0, "add an environment variable", 0 },
        { "cap", 'c', "CAP", 0, "add a capability", 0 },
        { "pid-file", OPTION_PID_FILE, "FILE", 0, "where to write the PID of the container", 0 },
        { "preserve-fds", OPTION_PRESERVE_FDS, "N", 0, "pass additional FDs to the container", 0 },
        { "no-new-privs", OPTION_NO_NEW_PRIVS, 0, 0, "set the no new privileges value for the process", 0 },
        { "process-label", OPTION_PROCESS_LABEL, "VALUE", 0, "set the asm process label for the process commonly used with selinux", 0 },
        { "apparmor", OPTION_APPARMOR, "VALUE", 0, "set the apparmor profile for the process", 0 },
        {
            0,
        } };

static char args_doc[] = "exec CONTAINER cmd";

static void
append_env (const char *arg)
{
  exec_options.env = realloc (exec_options.env, (exec_options.env_size + 2) * sizeof (*exec_options.env));
  if (exec_options.env == NULL)
    error (EXIT_FAILURE, errno, "cannot allocate memory");
  exec_options.env[exec_options.env_size + 1] = NULL;
  exec_options.env[exec_options.env_size] = xstrdup (arg);
  exec_options.env_size++;
}

static void
append_cap (const char *arg)
{
  exec_options.cap = realloc (exec_options.cap, (exec_options.cap_size + 2) * sizeof (*exec_options.cap));
  if (exec_options.cap == NULL)
    error (EXIT_FAILURE, errno, "cannot allocate memory");
  exec_options.cap[exec_options.cap_size + 1] = NULL;
  exec_options.cap[exec_options.cap_size] = xstrdup (arg);
  exec_options.cap_size++;
}

static char **
dup_array (char **arr, size_t len)
{
  size_t i;
  char **ret;

  ret = malloc (sizeof (char *) * (len + 1));
  if (ret == NULL)
    error (EXIT_FAILURE, errno, "cannot allocate memory");
  for (i = 0; i < len; i++)
    ret[i] = xstrdup (arr[i]);

  ret[i] = NULL;
  return ret;
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

    case OPTION_NO_NEW_PRIVS:
      exec_options.no_new_privs = true;
      break;

    case OPTION_PROCESS_LABEL:
      exec_options.process_label = argp_mandatory_argument (arg, state);
      break;

    case OPTION_APPARMOR:
      exec_options.apparmor = argp_mandatory_argument (arg, state);
      break;

    case OPTION_PRESERVE_FDS:
      exec_options.preserve_fds = strtoul (argp_mandatory_argument (arg, state), NULL, 10);
      break;

    case OPTION_CGROUP:
      exec_options.cgroup = argp_mandatory_argument (arg, state);
      break;

    case 'd':
      exec_options.detach = true;
      break;

    case 'p':
      exec_options.process = arg;
      break;

    case 't':
      exec_options.tty = arg == NULL || (strcmp (arg, "false") != 0 && strcmp (arg, "no") != 0);
      break;

    case 'u':
      exec_options.user = arg;
      break;

    case 'e':
      append_env (arg);
      break;

    case 'c':
      append_cap (arg);
      break;

    case OPTION_CWD:
      exec_options.cwd = xstrdup (arg);
      break;

    case ARGP_KEY_NO_ARGS:
      libcrun_fail_with_error (0, "please specify a ID for the container");

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

static runtime_spec_schema_config_schema_process_user *
make_oci_process_user (const char *userspec)
{
  runtime_spec_schema_config_schema_process_user *u;
  char *endptr = NULL;

  if (userspec == NULL)
    return NULL;

  u = xmalloc0 (sizeof (runtime_spec_schema_config_schema_process_user));
  errno = 0;
  u->uid = strtol (userspec, &endptr, 10);
  if (errno == ERANGE)
    libcrun_fail_with_error (0, "invalid UID specified");
  if (*endptr == '\0')
    return u;
  if (*endptr != ':')
    libcrun_fail_with_error (0, "invalid USERSPEC specified");

  errno = 0;
  u->gid = strtol (endptr + 1, &endptr, 10);
  if (errno == ERANGE)
    libcrun_fail_with_error (0, "invalid GID specified");
  if (*endptr != '\0')
    libcrun_fail_with_error (0, "invalid USERSPEC specified");

  return u;
}

#define cleanup_process_schema __attribute__ ((cleanup (cleanup_process_schemap)))

static inline void
cleanup_process_schemap (runtime_spec_schema_config_schema_process **p)
{
  runtime_spec_schema_config_schema_process *process = *p;
  if (process)
    (void) free_runtime_spec_schema_config_schema_process (process);
}

int
crun_command_exec (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg = 0, ret = 0;
  libcrun_context_t crun_context = {
    0,
  };
  cleanup_process_schema runtime_spec_schema_config_schema_process *process = NULL;
  struct libcrun_container_exec_options_s exec_opts;

  memset (&exec_opts, 0, sizeof (exec_opts));
  exec_opts.struct_size = sizeof (exec_opts);

  crun_context.preserve_fds = 0;
  crun_context.listen_fds = 0;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &exec_options);
  crun_assert_n_args (argc - first_arg, exec_options.process ? 1 : 2, -1);

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  crun_context.detach = exec_options.detach;
  crun_context.console_socket = exec_options.console_socket;
  crun_context.pid_file = exec_options.pid_file;
  crun_context.preserve_fds = exec_options.preserve_fds;

  if (getenv ("LISTEN_FDS"))
    {
      crun_context.listen_fds = strtoll (getenv ("LISTEN_FDS"), NULL, 10);
      crun_context.preserve_fds += crun_context.listen_fds;
    }

  if (exec_options.process)
    exec_opts.path = exec_options.process;
  else
    {
      process = xmalloc0 (sizeof (*process));
      int i;

      process->args_len = argc;
      process->args = xmalloc0 ((argc + 1) * sizeof (*process->args));
      for (i = 0; i < argc - first_arg; i++)
        process->args[i] = xstrdup (argv[first_arg + i + 1]);
      process->args[i] = NULL;
      if (exec_options.cwd)
        process->cwd = exec_options.cwd;
      process->terminal = exec_options.tty;
      process->env = exec_options.env;
      process->env_len = exec_options.env_size;
      process->user = make_oci_process_user (exec_options.user);

      if (exec_options.process_label != NULL)
        process->selinux_label = exec_options.process_label;

      if (exec_options.apparmor != NULL)
        process->apparmor_profile = exec_options.apparmor;

      if (exec_options.cap_size > 0)
        {
          runtime_spec_schema_config_schema_process_capabilities *capabilities
              = xmalloc (sizeof (runtime_spec_schema_config_schema_process_capabilities));

          capabilities->effective = exec_options.cap;
          capabilities->effective_len = exec_options.cap_size;

          capabilities->inheritable = NULL;
          capabilities->inheritable_len = 0;

          capabilities->bounding = dup_array (exec_options.cap, exec_options.cap_size);
          capabilities->bounding_len = exec_options.cap_size;

          capabilities->ambient = dup_array (exec_options.cap, exec_options.cap_size);
          capabilities->ambient_len = exec_options.cap_size;

          capabilities->permitted = dup_array (exec_options.cap, exec_options.cap_size);
          capabilities->permitted_len = exec_options.cap_size;

          process->capabilities = capabilities;
        }

      // noNewPriviledges will remain `false` if basespec has `false` unless specified
      // Default is always `true` in generated basespec config
      if (exec_options.no_new_privs)
        process->no_new_privileges = 1;

      exec_opts.process = process;
    }

  exec_opts.cgroup = exec_options.cgroup;

  return libcrun_container_exec_with_options (&crun_context, argv[first_arg], &exec_opts, err);
}
