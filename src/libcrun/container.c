/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
 * libocispec is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libocispec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE

#include <config.h>
#include <stdbool.h>
#include "container.h"
#include "utils.h"
#include "seccomp.h"
#include <argp.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#include "status.h"
#include "linux.h"
#include "terminal.h"
#include "cgroup.h"
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <systemd/sd-daemon.h>
#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>

enum
  {
    SYNC_SOCKET_SYNC_MESSAGE,
    SYNC_SOCKET_ERROR_MESSAGE,
    SYNC_SOCKET_WARNING_MESSAGE,
  };

struct container_entrypoint_s
{
  libcrun_container *container;
  struct libcrun_context_s *context;
  int has_terminal_socket_pair;
  int terminal_socketpair[2];
  int sync_socket;
};

struct sync_socket_message_s
{
  int type;
  int error_value;
  char message[512];
};

#define SYNC_SOCKET_MESSAGE_LEN(x, l) (offsetof (struct sync_socket_message_s, message) + l)

static int
sync_socket_write_msg (int fd, bool warning, int err_value, const char *log_msg)
{
  int ret;
  size_t err_len;
  struct sync_socket_message_s msg;
  msg.type = warning ? SYNC_SOCKET_WARNING_MESSAGE : SYNC_SOCKET_ERROR_MESSAGE;
  msg.error_value = err_value;

  err_len = strlen (log_msg);
  if (err_len > sizeof (msg.message))
    err_len = sizeof (msg.message) - 1;

  memcpy (msg.message, log_msg, err_len);
  msg.message[err_len] = '\0';

  ret = TEMP_FAILURE_RETRY (write (fd, &msg, SYNC_SOCKET_MESSAGE_LEN (msg, err_len + 1)));
  if (UNLIKELY (ret < 0))
    return -1;

  return 0;
}

static int
sync_socket_write_error (int fd, libcrun_error_t *out_err)
{
  return sync_socket_write_msg (fd, false, (*out_err)->status, (*out_err)->msg);
}

static void
log_write_to_sync_socket (int errno_, const char *msg, bool warning, void *arg)
{
  struct container_entrypoint_s *entrypoint_args = arg;
  int fd = entrypoint_args->sync_socket;

  if (sync_socket_write_msg (fd, warning, errno_, msg) < 0)
    log_write_to_stderr (errno_, msg, warning, arg);
}

static int
sync_socket_send_sync (int fd, libcrun_error_t *err)
{
  int ret;
  struct sync_socket_message_s msg;
  msg.type = SYNC_SOCKET_SYNC_MESSAGE;

  ret = TEMP_FAILURE_RETRY (write (fd, &msg, SYNC_SOCKET_MESSAGE_LEN (msg, 0)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write to sync socket");

  return 0;
}

static int
sync_socket_wait_sync (int fd, libcrun_error_t *err)
{
  int ret;
  struct sync_socket_message_s msg;

  while (true)
    {
      ret = TEMP_FAILURE_RETRY (read (fd, &msg, sizeof (msg)));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "read from sync socket");

      if (msg.type == SYNC_SOCKET_SYNC_MESSAGE)
        return 0;

      if (msg.type == SYNC_SOCKET_WARNING_MESSAGE)
        {
          log_write_to_stderr (msg.error_value, msg.message, 1, NULL);
          continue;
        }
      return crun_make_error (err, msg.error_value, "%s", msg.message);
    }
}

libcrun_container *
libcrun_container_load (const char *path, libcrun_error_t *err)
{
  libcrun_container *container;
  oci_container *container_def;
  cleanup_free char *oci_error = NULL;
  container_def = oci_container_parse_file (path, 0, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (err, 0, "load '%s': %s", path, oci_error);
      return NULL;
    }

  container = xmalloc (sizeof (*container));
  memset (container, 0, sizeof (*container));
  container->container_def = container_def;

  container->host_uid = getuid ();
  container->host_gid = getgid ();

  return container;
}

static
int block_signals (libcrun_error_t *err)
{
  int ret;
  sigset_t mask;
  sigfillset (&mask);
  ret = sigprocmask (SIG_BLOCK, &mask, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sigprocmask");
  return 0;
}

static
int unblock_signals (libcrun_error_t *err)
{
  int ret;
  sigset_t mask;
  sigfillset (&mask);
  ret = sigprocmask (SIG_UNBLOCK, &mask, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sigprocmask");
  return 0;
}

static int
set_uid_gid (libcrun_container *container, libcrun_error_t *err)
{
  uid_t uid = container->container_uid;
  gid_t gid = container->container_gid;

  if (gid && setgid (gid) < 0)
    return crun_make_error (err, errno, "setgid");
  if (uid && setuid (uid) < 0)
    return crun_make_error (err, errno, "setuid");
  return 0;
}

static int
container_entrypoint_init (void *args, const char *notify_socket,
                           int sync_socket, libcrun_error_t *err)
{
  struct container_entrypoint_s *entrypoint_args = args;
  libcrun_container *container = entrypoint_args->container;
  int ret;
  size_t i;
  int has_terminal;
  cleanup_close int console_socket = -1;
  cleanup_close int terminal_fd = -1;
  oci_container *def = container->container_def;
  cleanup_free char *rootfs = NULL;

  rootfs = realpath (def->root->path, NULL);
  if (UNLIKELY (rootfs == NULL))
    return crun_make_error (err, errno, "realpath");

  if (entrypoint_args->terminal_socketpair[0] >= 0)
    close (entrypoint_args->terminal_socketpair[0]);

  has_terminal = container->container_def->process->terminal;
  if (has_terminal && entrypoint_args->context->console_socket)
    {
      console_socket = open_unix_domain_socket (entrypoint_args->context->console_socket, 0, err);
      if (UNLIKELY (console_socket < 0))
        return console_socket;
    }

  ret = libcrun_set_mounts (container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (has_terminal)
    {
      ret = setsid ();
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "setsid");

      terminal_fd = libcrun_set_terminal (container, err);
      if (UNLIKELY (terminal_fd < 0))
        return ret;
      if (console_socket >= 0)
        {
          ret = send_fd_to_socket (console_socket, terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close (console_socket);
        }
      else if (entrypoint_args->has_terminal_socket_pair)
        {
          ret = send_fd_to_socket (entrypoint_args->terminal_socketpair[1], terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close (entrypoint_args->terminal_socketpair[1]);
        }
    }

  ret = libcrun_set_selinux_exec_label (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_hostname (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_oom (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_sysctl (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_caps (container, container->container_uid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_rlimits (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = set_uid_gid (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->container_uid)
    {
      ret = libcrun_set_caps (container, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (def->process->cwd)
    if (UNLIKELY (chdir (def->process->cwd) < 0))
      return crun_make_error (err, errno, "chdir");

  ret = libcrun_set_seccomp (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (clearenv ())
    return crun_make_error (err, errno, "clearenv");

  for (i = 0; i < def->process->env_len; i++)
    if (putenv (def->process->env[i]) < 0)
      return crun_make_error (err, errno, "putenv '%s'", def->process->env[i]);
  if (notify_socket)
    {
      char *notify_socket_env;
      xasprintf (&notify_socket_env, "NOTIFY_SOCKET=%s", notify_socket);
      if (putenv (notify_socket_env) < 0)
        return crun_make_error (err, errno, "putenv '%s'", notify_socket_env);
    }

  return 0;
}

/* Entrypoint to the container.  */
static int
container_entrypoint (void *args, const char *notify_socket,
                      int sync_socket, libcrun_error_t *err)
{
  struct container_entrypoint_s *entrypoint_args = args;
  int ret;
  oci_container *def = entrypoint_args->container->container_def;
  entrypoint_args->sync_socket = sync_socket;

  crun_set_output_handler (log_write_to_sync_socket, args);

  ret = container_entrypoint_init (args, notify_socket, sync_socket, err);
  if (UNLIKELY (ret < 0))
    {
      /* If it fails to write the error using the sync socket, then fallback
         to stderr.  */
      if (sync_socket_write_error (sync_socket, err) < 0)
        return ret;

      crun_error_release (err);
      return 0;
    }

  entrypoint_args->sync_socket = -1;
  crun_set_output_handler (log_write_to_stderr, NULL);

  ret = sync_socket_send_sync (sync_socket, err);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write to sync socket");

  ret = sync_socket_wait_sync (sync_socket, err);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read from the sync socket");

  ret = unblock_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (entrypoint_args->context->has_fifo_exec_wait)
    {
      char buffer[1];
      fd_set read_set;
      cleanup_close int fd = entrypoint_args->context->fifo_exec_wait_fd;
      entrypoint_args->context->fifo_exec_wait_fd = -1;

      FD_ZERO (&read_set);
      FD_SET (fd, &read_set);

      do
        {
          ret = select (fd + 1, &read_set, NULL, NULL, NULL);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "select");

          ret = TEMP_FAILURE_RETRY (read (fd, buffer, sizeof (buffer)));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "read from the exec fifo");
        }
      while (ret == 0);
    }

  ret = close_fds_ge_than (entrypoint_args->context->preserve_fds + 3, err);
  if (UNLIKELY (ret < 0))
    crun_error_write_warning_and_release (entrypoint_args->context->stderr, err);

  execvp (def->process->args[0], def->process->args);
  return crun_make_error (err, errno, "exec the container process");
}

struct hook_s
{
    char *path;
    char **args;
    size_t args_len;

    int timeout;
    char **env;
    size_t env_len;

};

static int
do_hooks (pid_t pid, const char *id, const char *rootfs, struct hook_s **hooks,
          size_t hooks_len, libcrun_error_t *err)
{
  size_t i, stdin_len;
  int ret;
  cleanup_free char *stdin = NULL;
  cleanup_free char *cwd = get_current_dir_name ();
  if (cwd == NULL)
    OOM ();

  stdin_len = xasprintf (&stdin, "{\"ociVersion\":\"1.0\", \"id\":\"%s\", \"pid\":%i, \"root\":\"%s\", \"bundle\":\"%s\"}", id, pid, rootfs, cwd);

  for (i = 0; i < hooks_len; i++)
    {
      ret = run_process_with_stdin_timeout_envp (hooks[i]->path, hooks[i]->args, hooks[i]->timeout, hooks[i]->env, stdin, stdin_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
run_poststop_hooks (struct libcrun_context_s *context, libcrun_container_status_t *status,
                    const char *state_root, const char *id, libcrun_error_t *err)
{
  libcrun_container *container;
  cleanup_free char *config_file = NULL;
  int ret;
  oci_container *def;

  xasprintf (&config_file, "%s/config.json", status->bundle);
  container = libcrun_container_load (config_file, err);
  if (container == NULL)
    libcrun_fail_with_error (0, "error loading config.json");

  def = container->container_def;
  if (def->hooks && def->hooks->poststop_len)
    {
      ret = do_hooks (0, id, def->root->path,
                      (struct hook_s **) def->hooks->poststop,
                      def->hooks->poststop_len, err);
      if (UNLIKELY (ret < 0))
        crun_error_write_warning_and_release (context->stderr, err);
    }
  return 0;
}

int
libcrun_delete_container (struct libcrun_context_s *context, const char *id, int force, libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status;
  const char *state_root = context->state_root;

  memset (&status, 0, sizeof (status));
  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    {
      if (force && crun_error_get_errno (err) == ENOENT)
        {
          libcrun_delete_container_status (state_root, id, err);
          crun_error_release (err);
          return 0;
        }
      goto exit;
    }

  if (force)
    {
      ret = kill (status.pid, 9);
      if (UNLIKELY (ret < 0) && errno != ESRCH)
        {
          crun_make_error (err, errno, "kill");
          goto error;
        }
    }
  else
    {
      ret = libcrun_is_container_running (&status, err);
      if (UNLIKELY (ret < 0))
        goto error;
      if (ret == 1)
        {
          crun_make_error (err, 0, "the container '%s' is still running", id);
          goto error;
        }
      if (UNLIKELY (ret < 0 && errno != ESRCH))
        {
          crun_make_error (err, errno, "signaling the container");
          goto error;
        }
    }

  if (status.cgroup_path)
    {
      ret = libcrun_cgroup_destroy (id, status.cgroup_path, status.systemd_cgroup, err);
      if (UNLIKELY (ret < 0))
        crun_error_write_warning_and_release (context->stderr, err);
    }

  ret = run_poststop_hooks (context, &status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    goto error;

 exit:
  ret = libcrun_delete_container_status (state_root, id, err);

 error:
  libcrun_free_container_status (&status);
  return ret;
}

int
libcrun_kill_container (struct libcrun_context_s *context, const char *id, int signal, libcrun_error_t *err)
{
  int ret;
  const char *state_root = context->state_root;
  libcrun_container_status_t status;
  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = kill (status.pid, signal);

  libcrun_free_container_status (&status);

  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "kill container");
  return 0;
}

static int
write_container_status (libcrun_container *container, struct libcrun_context_s *context, pid_t pid,
                        char *cgroup_path, char *created, libcrun_error_t *err)
{
  cleanup_free char *cwd = get_current_dir_name ();
  libcrun_container_status_t status = {.pid = pid,
                                       .cgroup_path = cgroup_path,
                                       .rootfs = container->container_def->root->path,
                                       .bundle = cwd,
                                       .created = created,
                                       .systemd_cgroup = context->systemd_cgroup};
  if (cwd == NULL)
    OOM ();
  return libcrun_write_container_status (context->state_root, context->id, &status, err);
}

static int
reap_subprocesses (pid_t main_process, int *main_process_exit, int *last_process, libcrun_error_t *err)
{
  *last_process = 0;
  while (1)
    {
      int status;
      int r = waitpid (-1, &status, WNOHANG);
      if (r < 0)
        {
          if (errno == EINTR)
            continue;
          if (errno == ECHILD)
            {
              *last_process = 1;
              return 0;
            }
          return crun_make_error (err, errno, "waitpid");
        }
      if (r == 0)
        break;
      if (r != main_process)
        continue;
      if (WIFEXITED (status) || WIFSIGNALED (status))
        *main_process_exit = WEXITSTATUS (status);
    }
  return 0;
}

static int
wait_for_process (pid_t pid, struct libcrun_context_s *context, int terminal_fd, int notify_socket, libcrun_error_t *err)
{
  cleanup_close int epollfd = -1;
  cleanup_close int signalfd = -1;
  int ret, container_exit_code, last_process;
  sigset_t mask;
  int fds[10];
  int levelfds[10];
  int levelfds_len = 0;
  int fds_len = 0;

  if (context->detach && notify_socket < 0)
    return 0;

  sigfillset (&mask);
  signalfd = create_signalfd (&mask, err);
  if (UNLIKELY (signalfd < 0))
    return signalfd;

  ret = sigprocmask (SIG_BLOCK, &mask, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sigprocmask");

  ret = reap_subprocesses (pid, &container_exit_code, &last_process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (last_process)
    return container_exit_code;

  fds[fds_len++] = signalfd;
  if (notify_socket >= 0)
    fds[fds_len++] = notify_socket;
  if (terminal_fd >= 0)
    {
      fds[fds_len++] = 0;
      levelfds[levelfds_len++] = terminal_fd;
    }
  fds[fds_len++] = -1;
  levelfds[levelfds_len++] = -1;

  epollfd = epoll_helper (fds, levelfds, err);
  if (UNLIKELY (epollfd < 0))
    return epollfd;

  while (1)
    {
      struct signalfd_siginfo si;
      ssize_t res;
      struct epoll_event events[10];
      int i, nr_events;

      nr_events = TEMP_FAILURE_RETRY (epoll_wait (epollfd, events, 10, -1));
      if (UNLIKELY (nr_events < 0))
        return crun_make_error (err, errno, "epoll_wait");

      for (i = 0; i < nr_events; i++)
        {
          if (events[i].data.fd == 0)
            {
              ret = copy_from_fd_to_fd (0, terminal_fd, 0, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
          else if (events[i].data.fd == terminal_fd)
            {
              ret = set_blocking_fd (terminal_fd, 0, err);
              if (UNLIKELY (ret < 0))
                return ret;

              ret = copy_from_fd_to_fd (terminal_fd, 1, 1, err);
              if (UNLIKELY (ret < 0))
                return ret;

              ret = set_blocking_fd (terminal_fd, 1, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
#ifdef HAVE_SYSTEMD
          else if (events[i].data.fd == notify_socket)
            {
              char buf[256];
              const char *ready_str = "READY=1";
              ret = recvfrom (notify_socket, buf, sizeof (buf) - 1, 0, NULL, NULL);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "recvfrom");
              buf[ret] = '\0';
              if (strstr (buf, ready_str))
                {
                  ret = sd_notify (0, ready_str);
                  if (UNLIKELY (ret < 0))
                    return crun_make_error (err, errno, "sd_notify");
                  if (context->detach)
                    return 0;
                }
            }
#endif
          else if (events[i].data.fd == signalfd)
            {
              res = TEMP_FAILURE_RETRY (read (signalfd, &si, sizeof (si)));
              if (UNLIKELY (res < 0))
                return crun_make_error (err, errno, "read from signalfd");
              if (si.ssi_signo == SIGCHLD)
                {
                  ret = reap_subprocesses (pid, &container_exit_code, &last_process, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  if (last_process)
                    return container_exit_code;
                }
              else
                {
                  /* Send any other signal to the child process.  */
                  ret = kill (pid, si.ssi_signo);
                }
            }
          else
            {
              return crun_make_error (err, 0, "unknown fd from epoll_wait");
            }
        }
    }

  return 0;
}

static void
flush_fd_to_err (int terminal_fd, FILE *stderr)
{
  char buf[256];
  int flags;
  if (terminal_fd < 0 || stderr == NULL)
    return;

  flags = fcntl (terminal_fd, F_GETFL, 0);
  if (flags == -1)
    return;
  if (fcntl (terminal_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return;

  for (;;)
    {
      int ret = read (terminal_fd, buf, sizeof (buf));
      if (ret <= 0)
        break;
      fwrite (buf, ret, 1, stderr);
    }
  fcntl (terminal_fd, F_SETFL, flags);
}

static void
cleanup_watch (struct libcrun_context_s *context, const char *id, int terminal_fd, FILE *stderr)
{
  libcrun_error_t err = NULL;
  libcrun_delete_container (context, id, 1, &err);
  crun_error_release (&err);

  flush_fd_to_err (terminal_fd, stderr);
}

static int
libcrun_container_run_internal (libcrun_container *container, struct libcrun_context_s *context, int container_ready_fd, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;
  pid_t pid;
  char c;
  int detach = context->detach;
  cleanup_free char *cgroup_path = NULL;
  cleanup_close int terminal_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_close int sync_socket = -1;
  cleanup_close int notify_socket = -1;
  cleanup_close int socket_pair_0 = -1;
  cleanup_close int socket_pair_1 = -1;
  char created[35];
  struct container_entrypoint_s container_args =
    {
      .container = container,
      .context = context,
      .terminal_socketpair = {-1, -1}
    };

  container->context = context;

  ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "set child subreaper");

  if (def->process->terminal && !detach && context->console_socket == NULL)
    {
      container_args.has_terminal_socket_pair = 1;
      ret = create_socket_pair (container_args.terminal_socketpair, err);
      if (UNLIKELY (ret < 0))
        return ret;
      socket_pair_0 = container_args.terminal_socketpair[0];
      socket_pair_1 = container_args.terminal_socketpair[1];
    }

  pid = libcrun_run_linux_container (container, context->detach,
                                     container_entrypoint, &container_args,
                                     &notify_socket, &sync_socket, err);
  if (UNLIKELY (pid < 0))
    return pid;

  if (container_args.terminal_socketpair[1] >= 0)
    {
      ret = close (container_args.terminal_socketpair[1]);
      socket_pair_1 = -1;
    }

  if (context->pid_file)
    {
      char buf[12];
      size_t buf_len = sprintf (buf, "%d", pid);
      ret = write_file (context->pid_file, buf, buf_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (def->process->terminal && !detach && context->console_socket == NULL)
    {
      terminal_fd = receive_fd_from_socket (container_args.terminal_socketpair[0], err);
      if (UNLIKELY (terminal_fd < 0))
        return terminal_fd;

      ret = libcrun_setup_terminal_master (terminal_fd, &orig_terminal, err);
      if (UNLIKELY (ret < 0))
        return ret;

      close (container_args.terminal_socketpair[0]);
    }

  ret = libcrun_cgroup_enter (&cgroup_path, def->linux->cgroups_path, context->systemd_cgroup, pid, context->id, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, context->id, terminal_fd, context->stderr);
      return ret;
    }

  ret = libcrun_set_cgroup_resources (container, cgroup_path, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, context->id, terminal_fd, context->stderr);
      return ret;
    }

  ret = sync_socket_wait_sync (sync_socket, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, context->id, terminal_fd, context->stderr);
      return ret;
    }

    /* The container is waiting that we write back.  In this phase we can launch the
       prestart hooks.  */
  if (def->hooks && def->hooks->prestart_len)
    {
      ret = do_hooks (pid, context->id, def->root->path,
                      (struct hook_s **) def->hooks->prestart,
                      def->hooks->prestart_len, err);
      if (UNLIKELY (ret < 0))
        {
          cleanup_watch (context, context->id, terminal_fd, context->stderr);
          return ret;
        }
    }

  ret = sync_socket_send_sync (sync_socket, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, context->id, terminal_fd, context->stderr);
      return crun_make_error (err, errno, "write to sync socket");
    }

  ret = close (sync_socket);
  sync_socket = -1;
  if (UNLIKELY (ret < 0))
    {
      flush_fd_to_err (terminal_fd, context->stderr);
      return crun_make_error (err, errno, "close the sync socket");
    }

  get_current_timestamp (created);
  ret = write_container_status (container, context, pid, cgroup_path, created, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, context->id, terminal_fd, context->stderr);
      return ret;
    }

  if (def->hooks && def->hooks->poststart_len)
    {
      ret = do_hooks (pid, context->id, def->root->path,
                      (struct hook_s **) def->hooks->poststart,
                      def->hooks->poststart_len, err);
      if (UNLIKELY (ret < 0))
        {
          cleanup_watch (context, context->id, terminal_fd, context->stderr);
          return ret;
        }
    }

  if (container_ready_fd >= 0)
    {
      TEMP_FAILURE_RETRY (write (container_ready_fd, "1", 1));
      close (container_ready_fd);
    }

  ret = wait_for_process (pid, context, terminal_fd, notify_socket, err);
  if (! context->has_fifo_exec_wait)
    cleanup_watch (context, context->id, terminal_fd, context->stderr);
  return ret;
}

static
int check_config_file (oci_container *def, libcrun_error_t *err)
{
  if (UNLIKELY (def->root == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'root' block specified");
  if (UNLIKELY (def->process == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'process' block specified");
  if (UNLIKELY (def->linux == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'linux' block specified");
  if (UNLIKELY (def->mounts == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'mounts' block specified");
  return 0;
}

int
libcrun_container_run (libcrun_container *container, struct libcrun_context_s *context, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;
  int detach = context->detach;

  container->context = context;

  ret = check_config_file (def, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process->terminal && detach && context->console_socket == NULL)
    return crun_make_error (err, 0, "use --console-socket with --detach when a terminal is used");

  if (!detach)
    {
      ret = block_signals (err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (context->stderr)
        stderr = context->stderr;
      return libcrun_container_run_internal (container, context, -1, err);
    }

  ret = fork ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fork");
  if (ret)
    return 0;

  if (context->stderr)
    stderr = context->stderr;

  /* forked process.  */
  ret = detach_process ();
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "detach process");
  libcrun_container_run_internal (container, context, -1, err);
  _exit (0);
}

int
libcrun_container_create (libcrun_container *container, struct libcrun_context_s *context, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;
  int tmp;
  int container_ready_pipe[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  cleanup_close int exec_fifo_fd = -1;
  context->detach = 1;
  container->context = context;

  ret = check_config_file (def, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  exec_fifo_fd = libcrun_status_create_exec_fifo (context->state_root, context->id, err);
  if (UNLIKELY (exec_fifo_fd < 0))
    return exec_fifo_fd;

  ret = pipe (container_ready_pipe);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipefd0 = container_ready_pipe[0];
  pipefd1 = container_ready_pipe[1];

  ret = fork ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fork");
  if (ret)
    {
      char c;
      close (pipefd1);
      pipefd1 = -1;

      ret = TEMP_FAILURE_RETRY (read (pipefd0, &c, 1));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "waiting for container to be ready");

      return 0;
    }

  context->has_fifo_exec_wait = 1;
  context->fifo_exec_wait_fd = exec_fifo_fd;
  exec_fifo_fd = -1;

  /* forked process.  */
  ret = detach_process ();
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "detach process");
  tmp = pipefd1;
  pipefd1 = -1;
  libcrun_container_run_internal (container, context, tmp, err);
  _exit (0);
}

int
libcrun_container_start (struct libcrun_context_s *context, const char *id, libcrun_error_t *err)
{
  int ret;
  const char *state_root = context->state_root;
  libcrun_container_status_t status;
  memset (&status, 0, sizeof (status));
  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (!ret)
    return crun_make_error (err, errno, "container '%s' is not running", id);

  return libcrun_status_write_exec_fifo (context->state_root, id, err);
}

int
libcrun_container_state (FILE *out, struct libcrun_context_s *context, const char *id, libcrun_error_t *err)
{
  int ret, running, has_fifo = 0;
  libcrun_container_status_t status;
  const char *state_root = context->state_root;
  const char *container_status;
  yajl_gen gen = NULL;
  const unsigned char *buf;
  size_t len;

  memset (&status, 0, sizeof (status));
  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    goto exit;
  running = ret;

  if (running)
    {
      ret = libcrun_status_has_read_exec_fifo (state_root, id, err);
      if (UNLIKELY (ret < 0))
        goto exit;
      has_fifo = ret;
    }

  if (! running)
    container_status = "stopped";
  else if (has_fifo)
    container_status = "created";
  else
    container_status = "running";

  ret = 0;
  gen = yajl_gen_alloc (NULL);
  if (gen == NULL)
    return crun_make_error (err, 0, "yajl_gen_alloc failed");

  yajl_gen_config (gen, yajl_gen_beautify, 1);
  yajl_gen_config (gen, yajl_gen_validate_utf8, 1);

  yajl_gen_map_open (gen);
#define YAJL_STR(x) ((const unsigned char *) (x))
  yajl_gen_string (gen, YAJL_STR ("ociVersion"), strlen ("ociVersion"));
  yajl_gen_string (gen, YAJL_STR ("1.0.0"), strlen ("1.0.0"));

  yajl_gen_string (gen, YAJL_STR ("id"), strlen ("id"));
  yajl_gen_string (gen, YAJL_STR (id), strlen (id));

  yajl_gen_string (gen, YAJL_STR ("pid"), strlen ("pid"));
  yajl_gen_integer (gen, running ? status.pid : 0);

  yajl_gen_string (gen, YAJL_STR ("status"), strlen ("status"));
  yajl_gen_string (gen, YAJL_STR (container_status), strlen (container_status));

  yajl_gen_string (gen, YAJL_STR ("bundle"), strlen ("bundle"));
  yajl_gen_string (gen, YAJL_STR (status.bundle), strlen (status.bundle));

  yajl_gen_string (gen, YAJL_STR ("rootfs"), strlen ("rootfs"));
  yajl_gen_string (gen, YAJL_STR (status.rootfs), strlen (status.rootfs));

  yajl_gen_string (gen, YAJL_STR ("created"), strlen ("created"));
  yajl_gen_string (gen, YAJL_STR (status.created), strlen (status.created));

  /* FIXME: store the owner.  */
  yajl_gen_string (gen, YAJL_STR ("owner"), strlen ("owner"));
  yajl_gen_string (gen, YAJL_STR (""), strlen (""));

  {
    size_t i;
    cleanup_free char *config_file;
    libcrun_container *container;

    xasprintf (&config_file, "%s/config.json", status.bundle);
    container = libcrun_container_load (config_file, err);
    if (UNLIKELY (container == NULL))
      return -1;

    if (container->container_def->annotations->len)
      {
        yajl_gen_string (gen, YAJL_STR ("annotations"), strlen ("annotations"));
        yajl_gen_map_open (gen);
        for (i = 0; i < container->container_def->annotations->len; i++)
          {
            const char *key = container->container_def->annotations->keys[i];
            const char *val = container->container_def->annotations->values[i];
            yajl_gen_string (gen, YAJL_STR (key), strlen (key));
            yajl_gen_string (gen, YAJL_STR (val), strlen (val));
          }
        yajl_gen_map_close (gen);
      }
   free_oci_container (container->container_def);
  }

  yajl_gen_map_close (gen);

  yajl_gen_get_buf (gen, &buf, &len);

  fprintf (out, "%s\n", buf);

 exit:
  if (gen)
    yajl_gen_free (gen);
  libcrun_free_container_status (&status);
  return ret;
}

int
libcrun_exec_container (struct libcrun_context_s *context, const char *id, int argc, char **argv, libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status;
  const char *state_root = context->state_root;
  cleanup_close int terminal_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  memset (&status, 0, sizeof (status));
  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (ret == 0)
    return crun_make_error (err, 0, "the container '%s' is not running.", id);

  if (!context->detach)
    {
      ret = block_signals (err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_join_process (status.pid, &status, context->detach, context->tty ? &terminal_fd : NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Process to exec.  */
  if (ret == 0)
    {
      const char *cwd = context->cwd ? context->cwd : "/";
      if (chdir (cwd) < 0)
        libcrun_fail_with_error (errno, "chdir");
      execv (argv[0], argv);
      _exit (1);
    }

  if (terminal_fd >= 0)
    {
      if (context->console_socket)
        {
          int ret;
          cleanup_close int console_socket_fd = open_unix_domain_socket (context->console_socket, 0, err);
          if (UNLIKELY (console_socket_fd < 0))
            return console_socket_fd;
          ret = send_fd_to_socket (console_socket_fd, terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close (terminal_fd);
          terminal_fd = -1;
        }
      else
        {
          ret = libcrun_setup_terminal_master (terminal_fd, &orig_terminal, err);
          if (UNLIKELY (ret < 0))
            {
              flush_fd_to_err (terminal_fd, context->stderr);
              return ret;
            }
        }
    }

  ret = wait_for_process (ret, context, terminal_fd, -1, err);
  flush_fd_to_err (terminal_fd, context->stderr);
  return ret;
}
