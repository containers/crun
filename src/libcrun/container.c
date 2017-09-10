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

libcrun_container *
libcrun_container_load (const char *path, libcrun_error_t *error)
{
  libcrun_container *container;
  oci_container *container_def;
  cleanup_free char *oci_error = NULL;
  container_def = oci_container_parse_file (path, 0, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (error, 0, "cannot parse configuration file: '%s'", oci_error);
      return NULL;
    }

  container = xmalloc (sizeof (*container));
  memset (container, 0, sizeof (*container));
  container->container_def = container_def;

  container->host_uid = getuid ();
  container->host_gid = getgid ();

  return container;
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

struct container_entrypoint_s
{
  libcrun_container *container;
  struct libcrun_context_s *opts;
  int has_terminal_socket_pair;
  int terminal_socketpair[2];
};

/* Entrypoint to the container.  */
static void
container_run (void *args, const char *notify_socket, int sync_socket)
{
  struct container_entrypoint_s *entrypoint_args = args;
  libcrun_container *container = entrypoint_args->container;
  libcrun_error_t err = NULL;
  int ret;
  size_t i;
  int has_terminal;
  cleanup_close int console_socket = -1;
  cleanup_close int terminal_fd = -1;
  oci_container *def = container->container_def;
  cleanup_free char *rootfs = NULL;

  rootfs = realpath (def->root->path, NULL);
  if (UNLIKELY (rootfs == NULL))
    {
      ret = crun_make_error (&err, errno, "realpath");
      goto out;
    }

  has_terminal = container->container_def->process->terminal;
  if (has_terminal && entrypoint_args->opts->console_socket)
    {
      console_socket = open_unix_domain_socket (entrypoint_args->opts->console_socket, 0, &err);
      if (UNLIKELY (console_socket < 0))
        goto out;
    }

  ret = libcrun_set_mounts (container, rootfs, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  if (has_terminal)
    {
      ret = setsid ();
      if (UNLIKELY (ret < 0))
        {
          ret = crun_make_error (&err, errno, "setsid");
          goto out;
        }
    }

  if (has_terminal)
    {
      terminal_fd = libcrun_set_terminal (container, &err);
      if (UNLIKELY (terminal_fd < 0))
        goto out;
      if (console_socket >= 0)
        {
          ret = send_fd_to_socket (console_socket, terminal_fd, &err);
          if (UNLIKELY (ret < 0))
            goto out;
        }
      else if (entrypoint_args->has_terminal_socket_pair)
        {
          ret = send_fd_to_socket (entrypoint_args->terminal_socketpair[1], terminal_fd, &err);
          if (UNLIKELY (ret < 0))
            goto out;
          close (entrypoint_args->terminal_socketpair[0]);
          close (entrypoint_args->terminal_socketpair[1]);
        }
    }

  ret = libcrun_set_selinux_exec_label (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  ret = libcrun_set_hostname (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  ret = libcrun_set_oom (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  ret = libcrun_set_sysctl (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  ret = libcrun_set_caps (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  ret = libcrun_set_rlimits (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  ret = set_uid_gid (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  if (def->process->cwd)
    if (UNLIKELY (chdir (def->process->cwd) < 0))
      {
        ret = crun_make_error (&err, errno, "chdir");
        goto out;
      }

  ret = libcrun_set_seccomp (container, &err);
  if (UNLIKELY (ret < 0))
    goto out;

  if (clearenv ())
    {
      ret = crun_make_error (&err, 0, "clearenv");
      goto out;
    }

  for (i = 0; i < def->process->env_len; i++)
    if (putenv (def->process->env[i]) < 0)
      {
        ret = crun_make_error (&err, 0, "putenv '%s'", def->process->env[i]);
        goto out;
      }
  if (notify_socket)
    {
      char *notify_socket_env;
      xasprintf (&notify_socket_env, "NOTIFY_SOCKET=%s", notify_socket);
      if (putenv (notify_socket_env) < 0)
        {
          ret = crun_make_error (&err, 0, "putenv '%s'", notify_socket_env);
          goto out;
        }
    }

  do
    {
      char c;
      ret = write (sync_socket, &c, 1);
    }
  while (ret < 0 && errno == EINTR);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (&err, errno, "write to the sync socket");
      goto out;
    }

  do
    {
      char c;
      ret = read (sync_socket, &c, 1);
    }
  while (ret < 0 && errno == EINTR);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (&err, errno, "read from the sync socket");
      goto out;
    }

  if (UNLIKELY (execvp (def->process->args[0], def->process->args) < 0))
    {
      ret = crun_make_error (&err, errno, "exec the container process");
      goto out;
    }

 out:
  error (EXIT_FAILURE, err->status, "%s", err->msg);
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
do_hooks (pid_t pid, const char *id, const char *rootfs, struct hook_s **hooks, size_t hooks_len, libcrun_error_t *err)
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
run_poststop_hooks (libcrun_container_status_t *status, const char *state_root, const char *id, libcrun_error_t *err)
{
  libcrun_container *container;
  cleanup_free char *config_file = NULL;
  int ret;
  oci_container *def;

  asprintf (&config_file, "%s/config.json", status->bundle);
  container = libcrun_container_load (config_file, err);
  if (container == NULL)
    error (EXIT_FAILURE, 0, "error loading config.json");

  def = container->container_def;
  if (def->hooks && def->hooks->poststop_len)
    {
      ret = do_hooks (0, id, def->root->path,
                      (struct hook_s **) def->hooks->poststop,
                      def->hooks->poststop_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

int
libcrun_delete_container (struct libcrun_context_s *run_options, const char *id, int force, libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status;
  const char *state_root = run_options->state_root;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  if (force)
    {
      ret = kill (status.pid, 9);
      if (UNLIKELY (ret < 0) && errno != ESRCH)
        return crun_make_error (err, errno, "kill");
    }
  else
    {
      ret = kill (status.pid, 0);
      if (ret == 0)
        return crun_make_error (err, 0, "the container '%s' is still running", id);
      if (UNLIKELY (ret < 0 && errno != ESRCH))
        return crun_make_error (err, errno, "signaling the container");
    }

  ret = run_poststop_hooks (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (status.cgroup_path)
    {
      ret = crun_path_exists (status.cgroup_path, 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret > 0)
        {
          ret = libcrun_cgroup_destroy (status.cgroup_path, err);
          if (UNLIKELY (ret < 0))
            crun_error_write_warning_and_release (run_options->stderr, err);
        }
    }
  libcrun_free_container_status (&status);

 exit:
  return libcrun_delete_container_status (state_root, id, err);
}

int
libcrun_kill_container (const char *state_root, const char *id, int signal, libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status;
  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = kill (status.pid, signal);

  libcrun_free_container_status (&status);

  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "kill container");
  return 0;
}

static int
write_container_status (libcrun_container *container, struct libcrun_context_s *opts, pid_t pid, char *cgroup_path, libcrun_error_t *err)
{
  cleanup_free char *cwd = get_current_dir_name ();
  libcrun_container_status_t status = {.pid = pid,
                                       .cgroup_path = cgroup_path,
                                       .rootfs = container->container_def->root->path,
                                       .bundle = cwd,
                                       .systemd_cgroup = opts->systemd_cgroup};
  if (cwd == NULL)
    OOM ();
  return libcrun_write_container_status (opts->state_root, opts->id, &status, err);
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
libcrun_container_run_internal (libcrun_container *container, struct libcrun_context_s *opts, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret, container_exit_code, last_process;
  pid_t pid;
  int detach = opts->detach;
  cleanup_free char *cgroup_path = NULL;
  cleanup_close int terminal_fd = -1;
  struct container_entrypoint_s container_args = {.container = container, .opts = opts};
  sigset_t mask;
  int fds[10];
  int fds_len = 0;
  cleanup_close int epollfd = -1;
  cleanup_close int signalfd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_close int sync_socket = -1;
  cleanup_close int notify_socket = -1;

  container->run_options = opts;

  ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "set child subreaper");

  if (def->process->terminal && !detach)
    {
      container_args.has_terminal_socket_pair = 1;
      ret = create_socket_pair (container_args.terminal_socketpair, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  pid = libcrun_run_container (container, opts->detach, container_run, &container_args, &notify_socket, &sync_socket, err);
  if (UNLIKELY (pid < 0))
    return pid;

  if (def->process->terminal && !detach)
    {
      terminal_fd = receive_fd_from_socket (container_args.terminal_socketpair[0], err);
      if (UNLIKELY (terminal_fd < 0))
        return terminal_fd;

      ret = libcrun_setup_terminal_master (terminal_fd, &orig_terminal, err);
      if (UNLIKELY (ret < 0))
        return ret;

      close (container_args.terminal_socketpair[0]);
      close (container_args.terminal_socketpair[1]);
    }

  ret = libcrun_cgroup_enter (&cgroup_path, opts->systemd_cgroup, pid, opts->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_cgroup_resources (container, cgroup_path, err);
  if (UNLIKELY (ret < 0))
    return ret;

  do
    {
      char c;
      ret = read (sync_socket, &c, 1);
    }
  while (ret < 0 && errno == EINTR);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "read from the sync socket");

    /* The container is waiting that we write back.  In this phase we can launch the
       prestart hooks.  */
  if (def->hooks && def->hooks->prestart_len)
    {
      ret = do_hooks (pid, opts->id, def->root->path,
                      (struct hook_s **) def->hooks->prestart,
                      def->hooks->prestart_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  do
    ret = write (sync_socket, "1", 1);
  while (ret < 0 && errno == EINTR);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "write to sync socket");

  ret = close (sync_socket);
  sync_socket = -1;
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, 0, "close the sync socket");

  ret = write_container_status (container, opts, pid, cgroup_path, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (opts->detach && notify_socket < 0)
    return 0;

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);
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
    {
      libcrun_delete_container (opts, opts->id, 1, err);
      return container_exit_code;
    }

  fds[fds_len++] = signalfd;
  if (notify_socket >= 0)
    fds[fds_len++] = notify_socket;
  if (terminal_fd >= 0)
    {
      fds[fds_len++] = 0;
      fds[fds_len++] = terminal_fd;
    }
  fds[fds_len++] = -1;

  epollfd = epoll_helper (fds, err);
  if (UNLIKELY (epollfd < 0))
    return epollfd;

  if (def->hooks && def->hooks->poststart_len)
    {
      ret = do_hooks (pid, opts->id, def->root->path,
                      (struct hook_s **) def->hooks->poststart,
                      def->hooks->poststart_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  while (1)
    {
      struct signalfd_siginfo si;
      ssize_t res;
      struct epoll_event events[10];
      int i, nr_events = epoll_wait (epollfd, events, 10, -1);
      if (UNLIKELY (nr_events < 0))
        return crun_make_error (err, errno, "epoll_wait");

      for (i = 0; i < nr_events; i++)
        {
          if (events[i].data.fd == 0)
            {
              ret = copy_from_fd_to_fd (0, terminal_fd, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
          else if (events[i].data.fd == terminal_fd)
            {
              ret = copy_from_fd_to_fd (terminal_fd, 0, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
          else if (events[i].data.fd == notify_socket)
            {
              char buf[256];
              ret = recvfrom (notify_socket, buf, sizeof (buf) - 1, 0, NULL, NULL);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "recvfrom");
              buf[ret] = '\0';
              if (strstr (buf, "READY=1"))
                {
                  ret = sd_notify (0, "READY=1");
                  if (UNLIKELY (ret < 0))
                    return crun_make_error (err, errno, "sd_notify");
                  if (opts->detach)
                    return 0;
                }
            }
          else if (events[i].data.fd == signalfd)
            {
              do
                res = read (signalfd, &si, sizeof(si));
              while (res < 0 && errno == EINTR);
              if (UNLIKELY (res < 0))
                return crun_make_error (err, errno, "read from signalfd");
              if (si.ssi_signo == SIGCHLD)
                {
                  ret = reap_subprocesses (pid, &container_exit_code, &last_process, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  if (last_process)
                    {
                      libcrun_delete_container (opts, opts->id, 1, err);
                      return container_exit_code;
                    }
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

int
libcrun_container_run (libcrun_container *container, struct libcrun_context_s *opts, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;
  int detach = opts->detach;

  container->run_options = opts;

  if (UNLIKELY (def->root == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'root' block specified");
  if (UNLIKELY (def->process == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'process' block specified");
  if (UNLIKELY (def->linux == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'linux' block specified");
  if (UNLIKELY (def->mounts == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'mounts' block specified");

  ret = libcrun_status_check_directories (opts->state_root, opts->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (!detach)
    return libcrun_container_run_internal (container, opts, err);

  ret = fork ();
  if (ret < 0)
    return crun_make_error (err, 0, "fork");
  if (ret)
    return 0;

  /* forked process.  */
  ret = detach_process ();
  if (ret < 0)
    error (EXIT_FAILURE, errno, "detach process");
  libcrun_container_run_internal (container, opts, err);
  _exit (0);
}
