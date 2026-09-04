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
#include <limits.h>

#include "crun.h"

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
append_to_string_array (char ***arr, size_t *size, const char *arg)
{
  *arr = xrealloc (*arr, (*size + 2) * sizeof (**arr));
  (*arr)[*size + 1] = NULL;
  (*arr)[*size] = xstrdup (arg);
  (*size)++;
}

static void
append_env (const char *arg)
{
  append_to_string_array (&exec_options.env, &exec_options.env_size, arg);
}

static void
append_cap (const char *arg)
{
  append_to_string_array (&exec_options.cap, &exec_options.cap_size, arg);
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
      exec_options.preserve_fds = parse_id_or_fail (argp_mandatory_argument (arg, state), NULL, "preserve-fds");
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

/* Minimal growable string buffer used to assemble the OCI Process JSON.  The
   binary is a pure consumer of the public API, so it builds the process as a
   JSON string rather than reaching for the internal ocispec types.  */
struct strbuf
{
  char *buf;
  size_t len;
  size_t cap;
};

static void
sb_ensure (struct strbuf *sb, size_t extra)
{
  if (sb->len + extra + 1 > sb->cap)
    {
      size_t ncap = sb->cap ? sb->cap : 256;
      while (ncap < sb->len + extra + 1)
        ncap *= 2;
      sb->buf = xrealloc (sb->buf, ncap);
      sb->cap = ncap;
    }
}

static void
sb_puts (struct strbuf *sb, const char *s)
{
  size_t l = strlen (s);
  sb_ensure (sb, l);
  memcpy (sb->buf + sb->len, s, l);
  sb->len += l;
  sb->buf[sb->len] = '\0';
}

static void
sb_putc (struct strbuf *sb, char c)
{
  sb_ensure (sb, 1);
  sb->buf[sb->len++] = c;
  sb->buf[sb->len] = '\0';
}

/* Append S as a quoted, escaped JSON string.  */
static void
sb_put_json_string (struct strbuf *sb, const char *s)
{
  sb_putc (sb, '"');
  for (; *s; s++)
    {
      unsigned char c = (unsigned char) *s;
      switch (c)
        {
        case '"':
          sb_puts (sb, "\\\"");
          break;
        case '\\':
          sb_puts (sb, "\\\\");
          break;
        case '\b':
          sb_puts (sb, "\\b");
          break;
        case '\f':
          sb_puts (sb, "\\f");
          break;
        case '\n':
          sb_puts (sb, "\\n");
          break;
        case '\r':
          sb_puts (sb, "\\r");
          break;
        case '\t':
          sb_puts (sb, "\\t");
          break;
        default:
          if (c < 0x20)
            {
              char tmp[8];
              snprintf (tmp, sizeof (tmp), "\\u%04x", c);
              sb_puts (sb, tmp);
            }
          else
            sb_putc (sb, c);
        }
    }
  sb_putc (sb, '"');
}

static void
sb_put_json_string_array (struct strbuf *sb, char **arr, size_t len)
{
  size_t i;
  sb_putc (sb, '[');
  for (i = 0; i < len; i++)
    {
      if (i)
        sb_putc (sb, ',');
      sb_put_json_string (sb, arr[i]);
    }
  sb_putc (sb, ']');
}

/* Read the whole file at PATH into a NUL-terminated string.  */
static char *
read_file_to_string (const char *path, libcrun_error_t *err)
{
  cleanup_file FILE *f = NULL;
  struct strbuf sb = { 0 };
  char chunk[4096];
  size_t n;

  f = fopen (path, "re");
  if (f == NULL)
    {
      libcrun_make_error (err, errno, "cannot open `%s`", path);
      return NULL;
    }

  while ((n = fread (chunk, 1, sizeof (chunk), f)) > 0)
    {
      sb_ensure (&sb, n);
      memcpy (sb.buf + sb.len, chunk, n);
      sb.len += n;
      sb.buf[sb.len] = '\0';
    }
  if (ferror (f))
    {
      free (sb.buf);
      libcrun_make_error (err, errno, "cannot read `%s`", path);
      return NULL;
    }

  if (sb.buf == NULL)
    sb.buf = xstrdup ("");
  return sb.buf;
}

/* Build the OCI Process JSON from the CLI options.  */
static char *
build_process_json (struct crun_global_arguments *global_args arg_unused, char **args, size_t args_len)
{
  struct strbuf sb = { 0 };

  sb_putc (&sb, '{');

  sb_puts (&sb, "\"args\":");
  sb_put_json_string_array (&sb, args, args_len);

  /* cwd is a required field in the OCI process schema; the exec path treats a
     missing value as "/".  */
  sb_puts (&sb, ",\"cwd\":");
  sb_put_json_string (&sb, exec_options.cwd ? exec_options.cwd : "/");

  sb_puts (&sb, ",\"terminal\":");
  sb_puts (&sb, exec_options.tty ? "true" : "false");

  if (exec_options.env_size > 0)
    {
      sb_puts (&sb, ",\"env\":");
      sb_put_json_string_array (&sb, exec_options.env, exec_options.env_size);
    }

  if (exec_options.user)
    {
      char *endptr = NULL;
      char *gidstr;
      int uid, gid = 0;
      char tmp[32];

      uid = parse_id_or_fail (exec_options.user, &endptr, "UID");
      if (*endptr == ':')
        {
          gidstr = endptr + 1;
          gid = parse_id_or_fail (gidstr, &endptr, "GID");
          if (*endptr != '\0')
            libcrun_fail_with_error (0, "invalid USERSPEC specified");
        }
      else if (*endptr != '\0')
        libcrun_fail_with_error (0, "invalid USERSPEC specified");

      sb_puts (&sb, ",\"user\":{\"uid\":");
      snprintf (tmp, sizeof (tmp), "%d", uid);
      sb_puts (&sb, tmp);
      sb_puts (&sb, ",\"gid\":");
      snprintf (tmp, sizeof (tmp), "%d", gid);
      sb_puts (&sb, tmp);
      sb_putc (&sb, '}');
    }

  if (exec_options.process_label != NULL)
    {
      sb_puts (&sb, ",\"selinuxLabel\":");
      sb_put_json_string (&sb, exec_options.process_label);
    }

  if (exec_options.apparmor != NULL)
    {
      sb_puts (&sb, ",\"apparmorProfile\":");
      sb_put_json_string (&sb, exec_options.apparmor);
    }

  if (exec_options.cap_size > 0)
    {
      sb_puts (&sb, ",\"capabilities\":{");
      sb_puts (&sb, "\"effective\":");
      sb_put_json_string_array (&sb, exec_options.cap, exec_options.cap_size);
      sb_puts (&sb, ",\"bounding\":");
      sb_put_json_string_array (&sb, exec_options.cap, exec_options.cap_size);
      sb_puts (&sb, ",\"ambient\":");
      sb_put_json_string_array (&sb, exec_options.cap, exec_options.cap_size);
      sb_puts (&sb, ",\"permitted\":");
      sb_put_json_string_array (&sb, exec_options.cap, exec_options.cap_size);
      sb_putc (&sb, '}');
    }

  /* noNewPrivileges remains at the config default unless explicitly requested.  */
  if (exec_options.no_new_privs)
    sb_puts (&sb, ",\"noNewPrivileges\":true");

  sb_putc (&sb, '}');

  return sb.buf;
}

int
crun_command_exec (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg = 0, ret = 0;
  cleanup_context libcrun_context_t *crun_context = NULL;
  cleanup_free char *process_json = NULL;
  struct libcrun_exec_options_s exec_opts;

  memset (&exec_opts, 0, sizeof (exec_opts));
  exec_opts.struct_size = sizeof (exec_opts);

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &exec_options);
  crun_assert_n_args (argc - first_arg, exec_options.process ? 1 : 2, -1);

  crun_context = new_libcrun_context (global_args);

  ret = init_libcrun_context (crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  libcrun_context_set_detach (crun_context, exec_options.detach);
  libcrun_context_set_console_socket (crun_context, exec_options.console_socket);
  libcrun_context_set_pid_file (crun_context, exec_options.pid_file);
  libcrun_context_set_preserve_fds (crun_context, exec_options.preserve_fds);

  if (getenv ("LISTEN_FDS"))
    {
      int listen_fds = strtoll (getenv ("LISTEN_FDS"), NULL, 10);
      libcrun_context_set_listen_fds (crun_context, listen_fds);
      libcrun_context_set_preserve_fds (crun_context, exec_options.preserve_fds + listen_fds);
    }

  if (exec_options.process)
    {
      process_json = read_file_to_string (exec_options.process, err);
      if (process_json == NULL)
        return -1;
      exec_opts.merge_env = false;
    }
  else
    {
      cleanup_free char **args = NULL;
      size_t args_len = argc - first_arg - 1;
      size_t i;

      args = xmalloc0 ((args_len + 1) * sizeof (*args));
      for (i = 0; i < args_len; i++)
        args[i] = argv[first_arg + i + 1];
      args[i] = NULL;

      process_json = build_process_json (global_args, args, args_len);
      exec_opts.merge_env = true;
    }

  exec_opts.process_json = process_json;
  exec_opts.cgroup = exec_options.cgroup;

  return libcrun_container_exec_with_options_json (crun_context, argv[first_arg], &exec_opts, err);
}
