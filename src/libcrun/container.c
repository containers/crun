/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
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
#include <stdbool.h>
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
#include <sys/ptrace.h>
#include <grp.h>

#ifdef HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>

enum
  {
    SYNC_SOCKET_SYNC_MESSAGE,
    SYNC_SOCKET_ERROR_MESSAGE,
    SYNC_SOCKET_WARNING_MESSAGE,
    SYNC_SOCKET_ABORT_MESSAGE,
  };

struct container_entrypoint_s
{
  libcrun_container *container;
  struct libcrun_context_s *context;
  int has_terminal_socket_pair;
  int terminal_socketpair[2];
  int sync_socket;
  int seccomp_fd;
  FILE *orig_stderr;
};

struct sync_socket_message_s
{
  int type;
  int error_value;
  char message[512];
};



static char spec_file[] = "\
  {\n\
	\"ociVersion\": \"1.0.0\",\n\
	\"process\": {\n\
		\"terminal\": true,\n\
		\"user\": {\n\
			\"uid\": 0,\n\
			\"gid\": 0\n\
		},\n\
		\"args\": [\n\
			\"sh\"\n\
		],\n\
		\"env\": [\n\
			\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\n\
			\"TERM=xterm\"\n\
		],\n\
		\"cwd\": \"/\",\n\
		\"capabilities\": {\n\
			\"bounding\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"effective\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"inheritable\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"permitted\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"ambient\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			]\n\
		},\n\
		\"rlimits\": [\n\
			{\n\
				\"type\": \"RLIMIT_NOFILE\",\n\
				\"hard\": 1024,\n\
				\"soft\": 1024\n\
			}\n\
		],\n\
		\"noNewPrivileges\": true\n\
	},\n\
	\"root\": {\n\
		\"path\": \"rootfs\",\n\
		\"readonly\": true\n\
	},\n\
	\"hostname\": \"crun\",\n\
	\"mounts\": [\n\
		{\n\
			\"destination\": \"/proc\",\n\
			\"type\": \"proc\",\n\
			\"source\": \"proc\"\n\
		},\n\
		{\n\
			\"destination\": \"/dev\",\n\
			\"type\": \"tmpfs\",\n\
			\"source\": \"tmpfs\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"strictatime\",\n\
				\"mode=755\",\n\
				\"size=65536k\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/dev/pts\",\n\
			\"type\": \"devpts\",\n\
			\"source\": \"devpts\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"newinstance\",\n\
				\"ptmxmode=0666\",\n\
				\"mode=0620\",\n\
				\"gid=5\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/dev/shm\",\n\
			\"type\": \"tmpfs\",\n\
			\"source\": \"shm\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\",\n\
				\"mode=1777\",\n\
				\"size=65536k\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/dev/mqueue\",\n\
			\"type\": \"mqueue\",\n\
			\"source\": \"mqueue\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/sys\",\n\
			\"type\": \"sysfs\",\n\
			\"source\": \"sysfs\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\",\n\
				\"ro\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/sys/fs/cgroup\",\n\
			\"type\": \"cgroup\",\n\
			\"source\": \"cgroup\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\",\n\
				\"relatime\",\n\
				\"ro\"\n\
			]\n\
		}\n\
	],\n\
	\"linux\": {\n\
		\"resources\": {\n\
			\"devices\": [\n\
				{\n\
					\"allow\": false,\n\
					\"access\": \"rwm\"\n\
				}\n\
			]\n\
		},\n\
		\"namespaces\": [\n\
			{\n\
				\"type\": \"pid\"\n\
			},\n\
			{\n\
				\"type\": \"network\"\n\
			},\n\
			{\n\
				\"type\": \"ipc\"\n\
			},\n\
			{\n\
				\"type\": \"uts\"\n\
			},\n\
%s\
			{\n\
				\"type\": \"mount\"\n\
			}\n\
		],\n\
		\"maskedPaths\": [\n\
			\"/proc/kcore\",\n\
			\"/proc/latency_stats\",\n\
			\"/proc/timer_list\",\n\
			\"/proc/timer_stats\",\n\
			\"/proc/sched_debug\",\n\
			\"/sys/firmware\"\n\
		],\n\
		\"readonlyPaths\": [\n\
			\"/proc/asound\",\n\
			\"/proc/bus\",\n\
			\"/proc/fs\",\n\
			\"/proc/irq\",\n\
			\"/proc/sys\",\n\
			\"/proc/sysrq-trigger\"\n\
		]\n\
	}\n\
}\n";

static const char *spec_user = "\
			{\n\
				\"type\": \"user\"\n \
			},\n";

#define SYNC_SOCKET_MESSAGE_LEN(x, l) (offsetof (struct sync_socket_message_s, message) + l)

static int
sync_socket_write_msg (int fd, bool warning, int err_value, const char *log_msg)
{
  int ret;
  size_t err_len;
  struct sync_socket_message_s msg;
  msg.type = warning ? SYNC_SOCKET_WARNING_MESSAGE : SYNC_SOCKET_ERROR_MESSAGE;
  msg.error_value = err_value;

  if (fd < 0)
    return 0;

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
  if (fd < 0)
    return 0;
  return sync_socket_write_msg (fd, false, (*out_err)->status, (*out_err)->msg);
}

static void
log_write_to_sync_socket (int errno_, const char *msg, bool warning, void *arg)
{
  struct container_entrypoint_s *entrypoint_args = arg;
  int fd = entrypoint_args->sync_socket;

  if (fd < 0)
    return;

  if (sync_socket_write_msg (fd, warning, errno_, msg) < 0)
    log_write_to_stderr (errno_, msg, warning, arg);
}

static int
sync_socket_wait_sync (int fd, bool flush, libcrun_error_t *err)
{
  int ret;
  struct sync_socket_message_s msg;

  if (fd < 0)
    return 0;

  while (true)
    {
      ret = TEMP_FAILURE_RETRY (read (fd, &msg, sizeof (msg)));
      if (UNLIKELY (ret < 0))
        {
          if (flush)
            return 0;
          return crun_make_error (err, errno, "read from sync socket");
        }

      if (ret == 0)
        {
          if (flush)
            return 0;
          return crun_make_error (err, errno, "sync socket closed");
        }

      if (!flush && msg.type == SYNC_SOCKET_SYNC_MESSAGE)
        return 0;

      if (msg.type == SYNC_SOCKET_ABORT_MESSAGE)
        {
          shutdown (fd, SHUT_RD);
          return crun_make_error (err, 0, "aborted");
        }

      if (msg.type == SYNC_SOCKET_WARNING_MESSAGE)
        {
          log_write_to_stderr (msg.error_value, msg.message, 1, NULL);
          continue;
        }
      if (msg.type == SYNC_SOCKET_ERROR_MESSAGE)
        {
          return crun_make_error (err, msg.error_value, "%s", msg.message);
        }

    }
}

static int
sync_socket_send_abort (int fd, libcrun_error_t *err)
{
  int ret;
  struct sync_socket_message_s msg;
  msg.type = SYNC_SOCKET_ABORT_MESSAGE;

  if (fd < 0)
    return 0;

  ret = TEMP_FAILURE_RETRY (write (fd, &msg, SYNC_SOCKET_MESSAGE_LEN (msg, 0)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write to sync socket");

  return 0;
}

static int
sync_socket_send_sync (int fd, bool flush_errors, libcrun_error_t *err)
{
  int ret;
  struct sync_socket_message_s msg;
  msg.type = SYNC_SOCKET_SYNC_MESSAGE;

  if (fd < 0)
    return 0;

  ret = TEMP_FAILURE_RETRY (write (fd, &msg, SYNC_SOCKET_MESSAGE_LEN (msg, 0)));
  if (UNLIKELY (ret < 0))
    {
      if (flush_errors)
        {
          ret = TEMP_FAILURE_RETRY (read (fd, &msg, sizeof (msg)));
          if (UNLIKELY (ret < 0))
            goto original_error;
          if (msg.type == SYNC_SOCKET_ERROR_MESSAGE)
            return crun_make_error (err, msg.error_value, "%s", msg.message);
        }
    original_error:
      return crun_make_error (err, errno, "write to sync socket");
    }

  return 0;
}

static libcrun_container *
make_container (oci_container *container_def)
{
  libcrun_container *container = xmalloc (sizeof (*container));
  memset (container, 0, sizeof (*container));
  container->container_def = container_def;

  container->host_uid = getuid ();
  container->host_gid = getgid ();

  return container;
}

libcrun_container *
libcrun_container_load_from_memory (const char *json, libcrun_error_t *err)
{
  oci_container *container_def;
  cleanup_free char *oci_error = NULL;
  container_def = oci_container_parse_data (json, NULL, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (err, 0, "load: %s", oci_error);
      return NULL;
    }
  return make_container (container_def);
}

libcrun_container *
libcrun_container_load_from_file (const char *path, libcrun_error_t *err)
{
  oci_container *container_def;
  cleanup_free char *oci_error = NULL;
  container_def = oci_container_parse_file (path, NULL, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (err, 0, "load '%s': %s", path, oci_error);
      return NULL;
    }
  return make_container (container_def);
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
container_entrypoint_init (void *args, const char *notify_socket,
                           int sync_socket, libcrun_error_t *err)
{
  struct container_entrypoint_s *entrypoint_args = args;
  libcrun_container *container = entrypoint_args->container;
  int ret;
  size_t i;
  int has_terminal;
  int old_stderr = -1;
  cleanup_close int console_socket = -1;
  cleanup_close int terminal_fd = -1;
  cleanup_close int console_socketpair = -1;
  oci_container *def = container->container_def;
  cleanup_free char *rootfs = NULL;

  rootfs = realpath (def->root->path, NULL);
  if (UNLIKELY (rootfs == NULL))
    return crun_make_error (err, errno, "realpath");

  if (entrypoint_args->terminal_socketpair[0] >= 0)
    {
      close_and_reset (&entrypoint_args->terminal_socketpair[0]);
      console_socketpair = entrypoint_args->terminal_socketpair[1];
    }

  ret = sync_socket_wait_sync (sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  has_terminal = container->container_def->process->terminal;
  if (has_terminal && entrypoint_args->context->console_socket)
    {
      console_socket = open_unix_domain_client_socket (entrypoint_args->context->console_socket, 0, err);
      if (UNLIKELY (console_socket < 0))
        return console_socket;
    }

#ifdef CLONE_NEWCGROUP
  ret = unshare (CLONE_NEWCGROUP);
  if (UNLIKELY (ret < 0))
    {
      if (errno != EINVAL)
	return crun_make_error (err, errno, "unshare (CLONE_NEWCGROUP)");
    }
#endif

  if (entrypoint_args->context->detach)
    {
      if (UNLIKELY (ptrace (PTRACE_TRACEME, 0, NULL, NULL) < 0))
        libcrun_fail_with_error (errno, "ptrace (PTRACE_TRACEME)");
    }

  ret = libcrun_set_mounts (container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (has_terminal)
    {
      ret = setsid ();
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "setsid");

      old_stderr = dup (2);
      if (old_stderr < 0)
        return crun_make_error (err, errno, "dup stderr");

      fflush (stderr);

      terminal_fd = libcrun_set_terminal (container, err);
      if (UNLIKELY (terminal_fd < 0))
        return terminal_fd;

      entrypoint_args->orig_stderr = fdopen (old_stderr, "a");
      if (UNLIKELY (entrypoint_args->orig_stderr == NULL))
        return crun_make_error (err, errno, "re-opening stderr");

      if (console_socket >= 0)
        {
          ret = send_fd_to_socket (console_socket, terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close_and_reset (&console_socket);
        }
      else if (entrypoint_args->has_terminal_socket_pair)
        {
          ret = send_fd_to_socket (console_socketpair, terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;

          close_and_reset (&console_socketpair);
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

  if (!def->process->no_new_privileges)
    {
      ret = libcrun_generate_and_load_seccomp (entrypoint_args->container, entrypoint_args->seccomp_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_set_caps (def->process->capabilities, def->process->no_new_privileges, container->container_uid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_rlimits (def->process->rlimits, def->process->rlimits_len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_set_uid_gid (container->container_uid, container->container_gid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->container_uid)
    {
      ret = libcrun_set_caps (def->process->capabilities, def->process->no_new_privileges, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (def->process->cwd)
    if (UNLIKELY (chdir (def->process->cwd) < 0))
      return crun_make_error (err, errno, "chdir");

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
      return ret;
    }

  entrypoint_args->sync_socket = -1;

  ret = sync_socket_send_sync (sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = sync_socket_wait_sync (sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = unblock_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  crun_set_output_handler (log_write_to_stream, entrypoint_args->orig_stderr);

  ret = close_fds_ge_than (entrypoint_args->context->preserve_fds + 3, err);
  if (UNLIKELY (ret < 0))
    crun_error_write_warning_and_release (entrypoint_args->context->stderr, &err);

  if (def->process->no_new_privileges)
    {
      ret = libcrun_generate_and_load_seccomp (entrypoint_args->container, entrypoint_args->seccomp_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  execvp (def->process->args[0], def->process->args);
  if (errno == ENOENT)
    return crun_make_error (err, errno, "executable file not found in $PATH");

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
do_hooks (pid_t pid, const char *id, bool keep_going, const char *rootfs,
          struct hook_s **hooks, size_t hooks_len, libcrun_error_t *err)
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
      if (!keep_going && UNLIKELY (ret != 0))
        return ret;
    }
  return 0;
}

static int
run_poststop_hooks (struct libcrun_context_s *context, oci_container *def,
                    libcrun_container_status_t *status,
                    const char *state_root, const char *id, libcrun_error_t *err)
{
  int ret;
  cleanup_free libcrun_container *container = NULL;
  if (def == NULL)
    {
      cleanup_free char *config_file = NULL;
      xasprintf (&config_file, "%s/config.json", status->bundle);
      container = libcrun_container_load_from_file (config_file, err);
      if (container == NULL)
        return crun_make_error (err, 0, "error loading config.json");

      def = container->container_def;
    }

  if (def->hooks && def->hooks->poststop_len)
    {
      ret = do_hooks (0, id, true, def->root->path,
                      (struct hook_s **) def->hooks->poststop,
                      def->hooks->poststop_len, err);
      if (UNLIKELY (ret < 0))
        crun_error_write_warning_and_release (context->stderr, &err);
    }
  if (container && container->container_def)
    free_oci_container (container->container_def);
  return 0;
}

static int
container_delete_internal (struct libcrun_context_s *context, oci_container *def, const char *id, bool force, bool only_cleanup, libcrun_error_t *err)
{
  int ret;
  cleanup_container_status libcrun_container_status_t status;
  const char *state_root = context->state_root;

  memset (&status, 0, sizeof (status));
  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    {
      if (force && crun_error_get_errno (err) == ENOENT)
        {
          libcrun_error_t tmp_err = NULL;

          crun_error_release (err);
          libcrun_container_delete_status (state_root, id, &tmp_err);
          crun_error_release (&tmp_err);
          return 0;
        }
      goto delete;
    }

  if (!only_cleanup && !status.detached)
    {
      if (force)
        {
          ret = kill (status.pid, 9);
          if (UNLIKELY (ret < 0) && errno != ESRCH)
            {
              crun_make_error (err, errno, "kill");
              return ret;
            }
        }
      else
        {
          ret = libcrun_is_container_running (&status, err);
          if (UNLIKELY (ret < 0))
            return ret;
          if (ret == 1)
            {
              ret = libcrun_status_has_read_exec_fifo (state_root, id, err);
              if (UNLIKELY (ret < 0))
                return ret;
              if (ret == 0)
                return crun_make_error (err, 0, "the container '%s' is still running", id);
              kill (status.pid, 9);
            }
        }
    }

  if (status.cgroup_path)
    {
      ret = libcrun_cgroup_destroy (id, status.cgroup_path, status.systemd_cgroup, err);
      if (UNLIKELY (ret < 0))
        crun_error_write_warning_and_release (context->stderr, &err);
    }

  ret = run_poststop_hooks (context, def, &status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    crun_error_write_warning_and_release (context->stderr, &err);

 delete:
  ret = libcrun_container_delete_status (state_root, id, err);

  return ret;
}

int
libcrun_container_delete (struct libcrun_context_s *context, oci_container *def, const char *id, bool force, libcrun_error_t *err)
{
  return container_delete_internal (context, def, id, force, false, err);
}

int
libcrun_container_kill (struct libcrun_context_s *context, const char *id, int signal, libcrun_error_t *err)
{
  int ret;
  const char *state_root = context->state_root;
  cleanup_container_status libcrun_container_status_t status;

  memset (&status, 0, sizeof (status));

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = kill (status.pid, signal);
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
                                       .systemd_cgroup = context->systemd_cgroup,
                                       .detached = context->detach};
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

      if (WIFSIGNALED (status))
        *main_process_exit = 128 + WTERMSIG (status);
      if (WIFEXITED (status))
        *main_process_exit = WEXITSTATUS (status);
    }
  return 0;
}

static int
wait_for_process (pid_t pid, struct libcrun_context_s *context, int terminal_fd, int notify_socket, int container_ready_fd, libcrun_error_t *err)
{
  cleanup_close int epollfd = -1;
  cleanup_close int signalfd = -1;
  int ret, container_exit_code = 0, last_process, pid_status;
  sigset_t mask;
  int fds[10];
  int levelfds[10];
  int levelfds_len = 0;
  int fds_len = 0;
  cleanup_close int exec_wait_fd = -1;

  container_exit_code = 0;

  /* On detach, the container uses PTRACEME.  In this case read its status after exec.  */
  if (context->detach)
    {
      ret = TEMP_FAILURE_RETRY (waitpid (pid, &pid_status, 0));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "waitpid for exec status");
      if (WIFSIGNALED (pid_status))
        container_exit_code = 128 + WTERMSIG (pid_status);
      if (WIFEXITED (pid_status))
        container_exit_code = WEXITSTATUS (pid_status);
    }

  if ((!context->detach || container_exit_code == 0) && context->pid_file)
    {
      char buf[12];
      size_t buf_len = sprintf (buf, "%d", pid);
      ret = write_file (context->pid_file, buf, buf_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* If the container process exited, return immediately when detach is used.  */
  if (context->detach && (container_exit_code || WIFEXITED (pid_status)))
    return container_exit_code;

  /* Also exit if there is nothing more to wait for.  */
  if (context->detach && notify_socket < 0 && context->fifo_exec_wait_fd < 0)
    return 0;

  if (container_ready_fd >= 0)
    {
      ret = 0;
      TEMP_FAILURE_RETRY (write (container_ready_fd, &ret, sizeof (ret)));
      close_and_reset (&container_ready_fd);
    }

  if (context->fifo_exec_wait_fd < 0)
    {
      ret = ptrace (PTRACE_DETACH, pid, NULL, NULL);
      if (UNLIKELY (ret < 0 && errno != ESRCH))
        return crun_make_error (err, errno, "ptrace");
    }

  sigfillset (&mask);
  ret = sigprocmask (SIG_BLOCK, &mask, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sigprocmask");

  signalfd = create_signalfd (&mask, err);
  if (UNLIKELY (signalfd < 0))
    return signalfd;

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
  if (context->fifo_exec_wait_fd >= 0)
    {
      exec_wait_fd = context->fifo_exec_wait_fd;
      fds[fds_len++] = exec_wait_fd;
      context->fifo_exec_wait_fd = -1;
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
          else if (events[i].data.fd == exec_wait_fd)
            {
              return 0;
            }
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
  fflush (stderr);
  fsync (1);
  fsync (2);
}

static void
cleanup_watch (struct libcrun_context_s *context, oci_container *def, const char *id, int sync_socket, int terminal_fd, FILE *stderr)
{
  libcrun_error_t err = NULL;
  container_delete_internal (context, def, id, 1, true, &err);
  crun_error_release (&err);

  sync_socket_send_abort (sync_socket, &err);
  if (err)
    crun_error_release (&err);

  sync_socket_wait_sync (sync_socket, true, &err);
  if (err)
    {
      log_write_to_stderr (err->status, err->msg, false, NULL);
      crun_error_release (&err);
    }

  if (terminal_fd >= 0)
    flush_fd_to_err (terminal_fd, stderr);
}

static
int open_seccomp_output (const char *id, int *fd, bool readonly, const char *state_root, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *dest_path = NULL;
  cleanup_free char *dir = NULL;

  dir = libcrun_get_state_directory (state_root, id);
  if (UNLIKELY (dir == NULL))
        return crun_make_error (err, 0, "cannot get state directory");

  xasprintf (&dest_path, "%s/seccomp.bpf", dir);

  *fd = -1;
  if (readonly)
    {
      ret = TEMP_FAILURE_RETRY (open (dest_path, O_RDONLY));
      if (UNLIKELY (ret < 0))
        {
          if (errno == ENOENT)
            return 0;
          return crun_make_error (err, 0, "open seccomp.bpf");
        }
      *fd = ret;
    }
  else
    {
      ret = TEMP_FAILURE_RETRY (open (dest_path, O_RDWR | O_CREAT, 0700));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "open seccomp.bpf");
      *fd = ret;
    }

  return 0;
}

static int
libcrun_container_run_internal (libcrun_container *container, struct libcrun_context_s *context, int container_ready_fd, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;
  pid_t pid;
  int detach = context->detach;
  bool skip_cgroups = false;
  cleanup_free char *cgroup_path = NULL;
  cleanup_close int terminal_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_close int sync_socket = -1;
  cleanup_close int notify_socket = -1;
  cleanup_close int socket_pair_0 = -1;
  cleanup_close int socket_pair_1 = -1;
  cleanup_close int seccomp_fd = -1;
  char created[35];
  struct container_entrypoint_s container_args =
    {
      .container = container,
      .context = context,
      .terminal_socketpair = {-1, -1},
      .orig_stderr = stderr
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

  ret = block_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->container_def->linux && container->container_def->linux->seccomp)
    {
      ret = open_seccomp_output (context->id, &seccomp_fd, false, context->state_root, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  container_args.seccomp_fd = seccomp_fd;

  pid = libcrun_run_linux_container (container, context->detach,
                                     container_entrypoint, &container_args,
                                     &notify_socket, &sync_socket, err);
  if (UNLIKELY (pid < 0))
    return pid;

  if (seccomp_fd >= 0)
    close_and_reset (&seccomp_fd);

  if (container_args.terminal_socketpair[1] >= 0)
    close_and_reset (&socket_pair_1);

  ret = libcrun_cgroup_enter (&cgroup_path, def->linux->cgroups_path, context->systemd_cgroup, pid, context->id, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
      return ret;
    }

  skip_cgroups = ret == 77;

  if (!skip_cgroups)
    {
      ret = libcrun_set_cgroup_resources (container, cgroup_path, err);
      if (UNLIKELY (ret < 0))
        {
          cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
          return ret;
        }
    }

  ret = sync_socket_send_sync (sync_socket, true, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
      return ret;
    }

  if (def->process->terminal && !detach && context->console_socket == NULL)
    {
      terminal_fd = receive_fd_from_socket (socket_pair_0, err);
      if (UNLIKELY (terminal_fd < 0))
        {
          cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
          return terminal_fd;
        }

      close_and_reset (&socket_pair_0);

      ret = libcrun_setup_terminal_master (terminal_fd, &orig_terminal, err);
      if (UNLIKELY (ret < 0))
        {
          cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
          return terminal_fd;
        }
    }

  ret = sync_socket_wait_sync (sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
      return ret;
    }

  /* The container is waiting that we write back.  In this phase we can launch the
     prestart hooks.  */
  if (def->hooks && def->hooks->prestart_len)
    {
      ret = do_hooks (pid, context->id, false, def->root->path,
                      (struct hook_s **) def->hooks->prestart,
                      def->hooks->prestart_len, err);
      if (UNLIKELY (ret != 0))
        {
          cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
          return ret;
        }
    }

  ret = sync_socket_send_sync (sync_socket, true, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
      return ret;
    }

  ret = close_and_reset (&sync_socket);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
      return ret;
    }

  get_current_timestamp (created);
  ret = write_container_status (container, context, pid, cgroup_path, created, err);
  if (UNLIKELY (ret < 0))
    {
      cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
      return ret;
    }

  if (def->hooks && def->hooks->poststart_len)
    {
      ret = do_hooks (pid, context->id, true, def->root->path,
                      (struct hook_s **) def->hooks->poststart,
                      def->hooks->poststart_len, err);
      if (UNLIKELY (ret < 0))
        {
          cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);
          return ret;
        }
    }

  ret = wait_for_process (pid, context, terminal_fd, notify_socket, container_ready_fd, err);
  if (!context->detach)
    cleanup_watch (context, def, context->id, sync_socket, terminal_fd, context->stderr);

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

static
int libcrun_copy_config_file (const char *id, const char *state_root, const char *bundle, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *src_path = NULL;
  cleanup_free char *dest_path = NULL;
  cleanup_free char *dir = NULL;
  cleanup_free char *buffer = NULL;
  size_t len;

  dir = libcrun_get_state_directory (state_root, id);
  if (UNLIKELY (dir == NULL))
        return crun_make_error (err, 0, "cannot get state directory");

  xasprintf (&src_path, "%s/config.json", bundle);
  xasprintf (&dest_path, "%s/config.json", dir);

  ret = read_all_file (src_path, &buffer, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = write_file (dest_path, buffer, len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

int
libcrun_container_run (struct libcrun_context_s *context, libcrun_container *container, unsigned int options, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;
  int detach = context->detach;
  int container_ret_status[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;

  container->context = context;

  ret = check_config_file (def, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->oci_version && strstr (def->oci_version, "1.0") == NULL)
    return crun_make_error (err, 0, "unknown version specified");

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_copy_config_file (context->id, context->state_root, context->bundle, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process->terminal && detach && context->console_socket == NULL)
    return crun_make_error (err, 0, "use --console-socket with --detach when a terminal is used");

  if (!detach && (options & LIBCRUN_RUN_OPTIONS_PREFORK) == 0)
    {
      if (context->stderr)
        stderr = context->stderr;
      return libcrun_container_run_internal (container, context, -1, err);
    }

  ret = pipe (container_ret_status);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipefd0 = container_ret_status[0];
  pipefd1 = container_ret_status[1];

  ret = fork ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fork");
  if (ret)
    {
      int status;
      close_and_reset (&pipefd1);
      TEMP_FAILURE_RETRY (waitpid (ret, &status, 0));

      ret = TEMP_FAILURE_RETRY (read (pipefd0, &status, sizeof (status)));
      if (UNLIKELY (ret < 0))
        return ret;

      if (status < 0)
        {
          int errno_;
          char buf[512];
          ret = TEMP_FAILURE_RETRY (read (pipefd0, &errno_, sizeof (errno_)));
          if (UNLIKELY (ret < 0))
            return ret;

          ret = TEMP_FAILURE_RETRY (read (pipefd0, buf, sizeof (buf) - 1));
          if (UNLIKELY (ret < 0))
            return ret;
          buf[ret] = '\0';

          return crun_make_error (err, errno_, buf);
        }

      return status;
    }

  close_and_reset (&pipefd0);

  if (context->stderr)
    stderr = context->stderr;

  /* forked process.  */
  ret = detach_process ();
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "detach process");
  ret = libcrun_container_run_internal (container, context, -1, err);
  TEMP_FAILURE_RETRY (write (pipefd1, &ret, sizeof (ret)));
  if (UNLIKELY (ret < 0))
    {
      TEMP_FAILURE_RETRY (write (pipefd1, &((*err)->status), sizeof ((*err)->status)));
      TEMP_FAILURE_RETRY (write (pipefd1, (*err)->msg, strlen ((*err)->msg) + 1));

      crun_set_output_handler (log_write_to_stderr, NULL);
      libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
    }
  exit (ret);
}

int
libcrun_container_create (struct libcrun_context_s *context, libcrun_container *container, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;
  int container_ready_pipe[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  cleanup_close int exec_fifo_fd = -1;
  context->detach = 1;

  container->context = context;

  if (def->oci_version && strstr (def->oci_version, "1.0") == NULL)
    return crun_make_error (err, 0, "unknown version specified");

  ret = check_config_file (def, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_copy_config_file (context->id, context->state_root, ".", err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process->terminal && context->console_socket == NULL)
    return crun_make_error (err, 0, "use --console-socket with create when a terminal is used");

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
      int exit_code;
      close_and_reset (&pipefd1);

      TEMP_FAILURE_RETRY (waitpid (ret, NULL, 0));

      ret = TEMP_FAILURE_RETRY (read (pipefd0, &exit_code, sizeof (exit_code)));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "waiting for container to be ready");
      if (ret > 0)
        {
          if (exit_code != 0)
            {
              libcrun_error_t tmp_err;
              libcrun_container_delete (context, def, context->id, true, &tmp_err);
              crun_error_release (err);
            }
          return -exit_code;
        }
      return 1;
    }

  if (context->stderr)
    stderr = context->stderr;

  context->fifo_exec_wait_fd = exec_fifo_fd;
  exec_fifo_fd = -1;

  /* forked process.  */
  ret = detach_process ();
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "detach process");

  ret = libcrun_container_run_internal (container, context, pipefd1, err);
  if (UNLIKELY (ret < 0))
    {
      crun_set_output_handler (log_write_to_stderr, NULL);
      log_write_to_stderr ((*err)->status, (*err)->msg, 0, NULL);
      fflush (stderr);
    }

  TEMP_FAILURE_RETRY (write (pipefd1, &ret, sizeof (ret)));
  exit (ret);
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
libcrun_container_state (struct libcrun_context_s *context, const char *id, FILE *out, libcrun_error_t *err)
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
    cleanup_free libcrun_container *container = NULL;
    cleanup_free char *dir = NULL;

    dir = libcrun_get_state_directory (state_root, id);
    if (UNLIKELY (dir == NULL))
      return crun_make_error (err, 0, "cannot get state directory");

    xasprintf (&config_file, "%s/config.json", dir);
    container = libcrun_container_load_from_file (config_file, err);
    if (UNLIKELY (container == NULL))
      return crun_make_error (err, 0, "error loading config.json");

    if (container->container_def->annotations && container->container_def->annotations->len)
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
libcrun_container_exec (struct libcrun_context_s *context, const char *id, oci_container_process *process, libcrun_error_t *err)
{
  int ret;
  pid_t pid;
  libcrun_container_status_t status;
  const char *state_root = context->state_root;
  cleanup_close int terminal_fd = -1;
  cleanup_close int seccomp_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_free char *config_file = NULL;

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

  ret = block_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = open_seccomp_output (context->id, &seccomp_fd, true, context->state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;


  pid = libcrun_join_process (status.pid, &status, context->detach, process->terminal ? &terminal_fd : NULL, err);
  if (UNLIKELY (pid < 0))
    return pid;

  /* Process to exec.  */
  if (pid == 0)
    {
      int i;
      uid_t container_uid = process->user ? process->user->uid : 0;
      const char *cwd = process->cwd ? process->cwd : "/";
      if (chdir (cwd) < 0)
        libcrun_fail_with_error (errno, "chdir");

      ret = unblock_signals (err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (context->detach)
        {
          if (UNLIKELY (ptrace (PTRACE_TRACEME, 0, NULL, NULL) < 0))
            libcrun_fail_with_error (errno, "ptrace (PTRACE_TRACEME)");
        }

      for (i = 0; i < process->env_len; i++)
        if (putenv (process->env[i]) < 0)
          libcrun_fail_with_error ( errno, "putenv '%s'", process->env[i]);

      if (process->selinux_label)
        {
          if (UNLIKELY (set_selinux_exec_label (process->selinux_label, err) < 0))
            libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
        }

      if (!process->no_new_privileges)
        {
          ret = libcrun_apply_seccomp (seccomp_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = libcrun_set_caps (process->capabilities, process->no_new_privileges, container_uid, err);
      if (UNLIKELY (ret < 0))
        libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

      ret = libcrun_set_rlimits (process->rlimits, process->rlimits_len, err);
      if (UNLIKELY (ret < 0))
        libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

      if (process->user)
        {
          if (process->user->additional_gids)
            {
              gid_t *additional_gids = process->user->additional_gids;
              size_t additional_gids_len = process->user->additional_gids_len;
              ret = setgroups (additional_gids_len, additional_gids);
              if (UNLIKELY (ret < 0))
                libcrun_fail_with_error (errno, "%s", "setgroups");
            }
          ret = libcrun_set_uid_gid (process->user->uid, process->user->gid, err);
          if (UNLIKELY (ret < 0))
            libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
        }

      if (process->user && process->user->uid)
        {
          ret = libcrun_set_caps (process->capabilities, process->no_new_privileges, 0, err);
          if (UNLIKELY (ret < 0))
            libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
        }

      ret = close_fds_ge_than (context->preserve_fds + 3, err);
      if (UNLIKELY (ret < 0))
        libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

      if (process->no_new_privileges)
        {
          ret = libcrun_apply_seccomp (seccomp_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = execvp (process->args[0], process->args);
      if (errno == ENOENT)
        libcrun_fail_with_error (errno, "executable file not found in $PATH");
      libcrun_fail_with_error (errno, "exec");
      _exit (1);
    }

  if (seccomp_fd >= 0)
    close_and_reset (&seccomp_fd);

  if (terminal_fd >= 0)
    {
      if (context->console_socket)
        {
          int ret;
          cleanup_close int console_socket_fd = open_unix_domain_client_socket (context->console_socket, 0, err);
          if (UNLIKELY (console_socket_fd < 0))
            return console_socket_fd;
          ret = send_fd_to_socket (console_socket_fd, terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close_and_reset (&terminal_fd);
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

  ret = wait_for_process (pid, context, terminal_fd, -1, -1, err);

  flush_fd_to_err (terminal_fd, context->stderr);
  return ret;
}

int
libcrun_container_exec_process_file (struct libcrun_context_s *context, const char *id, const char *path, libcrun_error_t *err)
{
  int ret;
  size_t len;
  cleanup_free char *content = NULL;
  struct parser_context ctx = {0, NULL};
  yajl_val tree = NULL;
  parser_error parser_err = NULL;
  oci_container_process *process = NULL;

  ret = read_all_file (path, &content, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = parse_json_file (&tree, content, &ctx, err);
  if (UNLIKELY (ret < 0))
    return ret;

  process = make_oci_container_process (tree, &ctx, &parser_err);
  if (UNLIKELY (process == NULL))
    {
      ret = crun_make_error (err, errno, "cannot parse process file");
      goto exit;
    }

  ret = libcrun_container_exec (context, id, process, err);

 exit:
  free (parser_err);

  if (tree)
    yajl_tree_free (tree);

  if (process)
    free_oci_container_process (process);

  return ret;
}

int
libcrun_container_update (struct libcrun_context_s *context, const char *id, const char *content, size_t len, libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status;
  const char *state_root = context->state_root;

  memset (&status, 0, sizeof (status));
  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return libcrun_linux_container_update (&status, content, len, err);
}

int
libcrun_container_spec (bool root, FILE *out, libcrun_error_t *err)
{

  return fprintf (out, spec_file, root ? "" : spec_user);
}
