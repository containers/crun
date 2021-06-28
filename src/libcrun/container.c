/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
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
#include <runtime_spec_schema_config_schema.h>
#include <stdbool.h>
#include "container.h"
#include "utils.h"
#include "seccomp.h"
#include "seccomp_notify.h"
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
#include <grp.h>
#include "kontain.h"

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#ifdef HAVE_LIBKRUN
#  include <libkrun.h>
#endif

#ifdef HAVE_SYSTEMD
#  include <systemd/sd-daemon.h>
#endif

#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>

#define YAJL_STR(x) ((const unsigned char *) (x))

enum
{
  SYNC_SOCKET_SYNC_MESSAGE,
  SYNC_SOCKET_ERROR_MESSAGE,
  SYNC_SOCKET_WARNING_MESSAGE,
};

struct container_entrypoint_s
{
  libcrun_container_t *container;
  libcrun_context_t *context;
  int has_terminal_socket_pair;
  int terminal_socketpair[2];

  /* Used by log_write_to_sync_socket.  */
  int sync_socket;

  int seccomp_fd;
  int seccomp_receiver_fd;
  int console_socket_fd;

  int hooks_out_fd;
  int hooks_err_fd;

  /* If specified, it is called instead of
     execve.  */
  int (*exec_func) (void *container, void *arg, const char *pathname, char *const argv[]);
  void *exec_func_arg;
};

struct sync_socket_message_s
{
  int type;
  int error_value;
  char message[512];
};

typedef runtime_spec_schema_defs_hook hook;

static const char spec_file[] = "\
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
				\"mode=0620\"\
%s\
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
%s\
			{\n\
				\"type\": \"mount\"\n\
			}\n\
		],\n\
		\"maskedPaths\": [\n\
			\"/proc/acpi\",\n\
			\"/proc/asound\",\n\
			\"/proc/kcore\",\n\
			\"/proc/keys\",\n\
			\"/proc/latency_stats\",\n\
			\"/proc/timer_list\",\n\
			\"/proc/timer_stats\",\n\
			\"/proc/sched_debug\",\n\
			\"/sys/firmware\",\n\
			\"/proc/scsi\"\n\
		],\n\
		\"readonlyPaths\": [\n\
			\"/proc/bus\",\n\
			\"/proc/fs\",\n\
			\"/proc/irq\",\n\
			\"/proc/sys\",\n\
			\"/proc/sysrq-trigger\"\n\
		]\n\
	}\n\
}\n";

static const char *spec_pts_tty_group = ",\n\
				\"gid=5\"\n";

static const char *spec_user = "\
			{\n\
				\"type\": \"user\"\n \
			},\n";

static const char *spec_cgroupns = "\
			{\n\
				\"type\": \"cgroup\"\n \
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
  if (err_len >= sizeof (msg.message))
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

static bool
is_memory_limit_too_low (runtime_spec_schema_config_schema *def)
{
  const long memory_limit_too_low = 1024 * 1024;

  if (def->linux == NULL || def->linux->resources == NULL)
    return false;

  if (def->linux->resources->memory
      && def->linux->resources->memory->limit_present
      && def->linux->resources->memory->limit < memory_limit_too_low)
    return true;

  if (def->linux->resources->unified)
    {
      size_t i;

      for (i = 0; i < def->linux->resources->unified->len; i++)
        if (strcmp (def->linux->resources->unified->keys[i], "memory.max") == 0)
          {
            long limit;

            errno = 0;
            limit = strtol (def->linux->resources->unified->values[i], NULL, 10);
            if (errno != 0)
              return false;
            if (limit < memory_limit_too_low)
              return true;
          }
    }

  return false;
}

static int
sync_socket_wait_sync (libcrun_context_t *context, int fd, bool flush, libcrun_error_t *err)
{
  struct sync_socket_message_s msg;

  if (fd < 0)
    return 0;

  while (true)
    {
      int ret;

      errno = 0;
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

          return crun_make_error (err, errno, "read from the init process");
        }

      if (! flush && msg.type == SYNC_SOCKET_SYNC_MESSAGE)
        return 0;

      if (msg.type == SYNC_SOCKET_WARNING_MESSAGE)
        {
          if (context)
            context->output_handler (msg.error_value, msg.message, 1, context->output_handler_arg);
          continue;
        }
      if (msg.type == SYNC_SOCKET_ERROR_MESSAGE)
        return crun_make_error (err, msg.error_value, "%s", msg.message);
    }
}

static int
sync_socket_send_sync (int fd, bool flush_errors, libcrun_error_t *err)
{
  int ret;
  struct sync_socket_message_s msg = {
    0,
  };
  msg.type = SYNC_SOCKET_SYNC_MESSAGE;

  if (fd < 0)
    return 0;

  ret = TEMP_FAILURE_RETRY (write (fd, &msg, SYNC_SOCKET_MESSAGE_LEN (msg, 0)));
  if (UNLIKELY (ret < 0))
    {
      if (flush_errors)
        {
          int saved_errno = errno;
          ret = TEMP_FAILURE_RETRY (read (fd, &msg, sizeof (msg)));
          if (ret >= 0 && msg.type == SYNC_SOCKET_ERROR_MESSAGE)
            return crun_make_error (err, msg.error_value, "%s", msg.message);
          errno = saved_errno;
        }
      return crun_make_error (err, errno, "write to sync socket");
    }

  return 0;
}

/*
  Create an intermediate user namespace if there is a single id mapped
  inside of the container user namespace and the container wants to run
  with a different UID/GID than root.
*/
static bool
need_intermediate_userns (runtime_spec_schema_config_schema *def)
{
  runtime_spec_schema_config_schema_process *process = def->process;
  uid_t container_uid;
  gid_t container_gid;

  if (process == NULL)
    return false;

  container_uid = process->user ? process->user->uid : 0;
  container_gid = process->user ? process->user->gid : 0;

  if (container_uid == 0 && container_gid == 0)
    return false;

  if (def->linux == NULL)
    return false;

  if (def->linux->uid_mappings_len != 1 || def->linux->gid_mappings_len != 1)
    return false;

  if (def->linux->uid_mappings[0]->size != 1 || def->linux->gid_mappings[0]->size != 1)
    return false;

  if (def->linux->uid_mappings[0]->container_id == container_uid
      && def->linux->gid_mappings[0]->container_id == container_gid)
    return false;

  return true;
}

static libcrun_container_t *
make_container (runtime_spec_schema_config_schema *container_def)
{
  libcrun_container_t *container = xmalloc0 (sizeof (*container));
  container->container_def = container_def;

  container->host_uid = geteuid ();
  container->host_gid = getegid ();

  container->use_intermediate_userns = need_intermediate_userns (container_def);

  return container;
}

libcrun_container_t *
libcrun_container_load_from_memory (const char *json, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *container_def;
  cleanup_free char *oci_error = NULL;
  container_def = runtime_spec_schema_config_schema_parse_data (json, NULL, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (err, 0, "load: %s", oci_error);
      return NULL;
    }
  return make_container (container_def);
}

libcrun_container_t *
libcrun_container_load_from_file (const char *path, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *container_def;
  cleanup_free char *oci_error = NULL;
  container_def = runtime_spec_schema_config_schema_parse_file (path, NULL, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (err, 0, "load `%s`: %s", path, oci_error);
      return NULL;
    }
  return make_container (container_def);
}

void
libcrun_container_free (libcrun_container_t *ctr)
{
  if (ctr == NULL)
    return;

  if (ctr->container_def)
    free_runtime_spec_schema_config_schema (ctr->container_def);
  free (ctr);
}

static int
block_signals (libcrun_error_t *err)
{
  int ret;
  sigset_t mask;
  sigfillset (&mask);
  ret = sigprocmask (SIG_BLOCK, &mask, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sigprocmask");
  return 0;
}

static int
unblock_signals (libcrun_error_t *err)
{
  int i;
  int ret;
  sigset_t mask;
  struct sigaction act = {};

  sigfillset (&mask);
  ret = sigprocmask (SIG_UNBLOCK, &mask, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sigprocmask");

  act.sa_handler = SIG_DFL;
  for (i = 0; i < NSIG; i++)
    {
      ret = sigaction (i, &act, NULL);
      if (ret < 0 && errno != EINVAL)
        return crun_make_error (err, errno, "sigaction");
    }

  return 0;
}

/* must be used on the host before pivot_root(2).  */
static int
initialize_security (runtime_spec_schema_config_schema_process *proc, libcrun_error_t *err)
{
  int ret;

  if (UNLIKELY (proc == NULL))
    return 0;

  if (proc->apparmor_profile)
    {
      ret = libcrun_initialize_apparmor (err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_initialize_selinux (err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_init_caps (err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
do_hooks (runtime_spec_schema_config_schema *def, pid_t pid, const char *id, bool keep_going, const char *cwd,
          const char *status, hook **hooks, size_t hooks_len, int out_fd, int err_fd, libcrun_error_t *err)
{
  size_t i, stdin_len;
  int r, ret;
  char *stdin = NULL;
  cleanup_free char *cwd_allocated = NULL;
  const char *rootfs = def->root ? def->root->path : "";
  yajl_gen gen = NULL;

  if (cwd == NULL)
    {
      cwd = cwd_allocated = getcwd (NULL, 0);
      if (cwd == NULL)
        OOM ();
    }

  gen = yajl_gen_alloc (NULL);
  if (gen == NULL)
    return crun_make_error (err, 0, "yajl_gen_alloc failed");

  r = yajl_gen_map_open (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("ociVersion"), strlen ("ociVersion"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("1.0"), strlen ("1.0"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("id"), strlen ("id"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR (id), strlen (id));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("pid"), strlen ("pid"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_integer (gen, pid);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("root"), strlen ("root"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR (rootfs), strlen (rootfs));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("bundle"), strlen ("bundle"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR (cwd), strlen (cwd));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR ("status"), strlen ("status"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_string (gen, YAJL_STR (status), strlen (status));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  if (def && def->annotations && def->annotations->len)
    {
      r = yajl_gen_string (gen, YAJL_STR ("annotations"), strlen ("annotations"));
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto yajl_error;

      r = yajl_gen_map_open (gen);
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto yajl_error;

      for (i = 0; i < def->annotations->len; i++)
        {
          const char *key = def->annotations->keys[i];
          const char *val = def->annotations->values[i];

          r = yajl_gen_string (gen, YAJL_STR (key), strlen (key));
          if (UNLIKELY (r != yajl_gen_status_ok))
            goto yajl_error;

          r = yajl_gen_string (gen, YAJL_STR (val), strlen (val));
          if (UNLIKELY (r != yajl_gen_status_ok))
            goto yajl_error;
        }
      r = yajl_gen_map_close (gen);
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto yajl_error;
    }

  r = yajl_gen_map_close (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  r = yajl_gen_get_buf (gen, (const unsigned char **) &stdin, &stdin_len);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto yajl_error;

  ret = 0;

  for (i = 0; i < hooks_len; i++)
    {
      ret = run_process_with_stdin_timeout_envp (hooks[i]->path, hooks[i]->args, cwd, hooks[i]->timeout, hooks[i]->env,
                                                 stdin, stdin_len, out_fd, err_fd, err);
      if (UNLIKELY (ret != 0))
        {
          if (keep_going)
            libcrun_warning ("error executing hook `%s` (exit code: %d)", hooks[i]->path, ret);
          else
            {
              libcrun_error (0, "error executing hook `%s` (exit code: %d)", hooks[i]->path, ret);
              break;
            }
        }
    }

  if (gen)
    yajl_gen_free (gen);

  return ret;

yajl_error:
  if (gen)
    yajl_gen_free (gen);
  return yajl_error_to_crun_error (r, err);
}

#if HAVE_DLOPEN && HAVE_LIBKRUN
static int
libkrun_do_exec (void *container, void *arg, const char *pathname, char *const argv[])
{
  runtime_spec_schema_config_schema *def = ((libcrun_container_t *) container)->container_def;
  int32_t (*krun_create_ctx) ();
  int (*krun_start_enter) (uint32_t ctx_id);
  int32_t (*krun_set_vm_config) (uint32_t ctx_id, uint8_t num_vcpus, uint32_t ram_mib);
  int32_t (*krun_set_root) (uint32_t ctx_id, const char *root_path);
  int32_t (*krun_set_workdir) (uint32_t ctx_id, const char *workdir_path);
  int32_t (*krun_set_exec) (uint32_t ctx_id, const char *exec_path, char *const argv[], char *const envp[]);
  void *handle = arg;
  uint32_t num_vcpus, ram_mib;
  int32_t ctx_id, ret;
  cpu_set_t set;

  krun_create_ctx = dlsym (handle, "krun_create_ctx");
  krun_start_enter = dlsym (handle, "krun_start_enter");
  krun_set_vm_config = dlsym (handle, "krun_set_vm_config");
  krun_set_root = dlsym (handle, "krun_set_root");
  krun_set_workdir = dlsym (handle, "krun_set_workdir");
  krun_set_exec = dlsym (handle, "krun_set_exec");
  if (krun_create_ctx == NULL || krun_start_enter == NULL || krun_set_vm_config == NULL || krun_set_root == NULL
      || krun_set_exec == NULL)
    {
      fprintf (stderr, "could not find symbol in `libkrun.so`");
      dlclose (handle);
      return -1;
    }

  /* If sched_getaffinity fails, default to 1 vcpu.  */
  num_vcpus = 1;
  /* If no memory limit is specified, default to 2G.  */
  ram_mib = 2 * 1024;

  if (def && def->linux && def->linux->resources && def->linux->resources->memory
      && def->linux->resources->memory->limit_present)
    ram_mib = def->linux->resources->memory->limit / (1024 * 1024);

  CPU_ZERO (&set);
  if (sched_getaffinity (getpid (), sizeof (set), &set) == 0)
    num_vcpus = CPU_COUNT (&set);

  ctx_id = krun_create_ctx ();
  if (UNLIKELY (ctx_id < 0))
    error (EXIT_FAILURE, -ret, "could not create krun context");

  ret = krun_set_vm_config (ctx_id, num_vcpus, ram_mib);
  if (UNLIKELY (ret < 0))
    error (EXIT_FAILURE, -ret, "could not set krun vm configuration");

  ret = krun_set_root (ctx_id, "/");
  if (UNLIKELY (ret < 0))
    error (EXIT_FAILURE, -ret, "could not set krun root");

  if (krun_set_workdir && def && def->process && def->process->cwd)
    {
      ret = krun_set_workdir (ctx_id, def->process->cwd);
      if (UNLIKELY (ret < 0))
        error (EXIT_FAILURE, -ret, "could not set krun working directory");
    }

  ret = krun_set_exec (ctx_id, pathname, &argv[1], NULL);
  if (UNLIKELY (ret < 0))
    error (EXIT_FAILURE, -ret, "could not set krun executable");

  return krun_start_enter (ctx_id);
}
#endif

static int
libcrun_configure_libkrun (struct container_entrypoint_s *args, libcrun_error_t *err)
{
#if HAVE_DLOPEN && HAVE_LIBKRUN
  void *handle;
#endif

#if HAVE_DLOPEN && HAVE_LIBKRUN
  handle = dlopen ("libkrun.so", RTLD_NOW);
  if (handle == NULL)
    return crun_make_error (err, 0, "could not load `libkrun.so`: %s", dlerror ());

  args->exec_func = libkrun_do_exec;
  args->exec_func_arg = handle;

  return 0;
#else
  (void) args;
  return crun_make_error (err, ENOTSUP, "libkrun or dlopen not present");
#endif
}

static int
libcrun_configure_handler (struct container_entrypoint_s *args, libcrun_error_t *err)
{
  const char *annotation;

  annotation = find_annotation (args->container, "run.oci.handler");
  /*Nothing to do.  */
  if (annotation == NULL)
    return 0;

  if (strcmp (annotation, "krun") == 0)
    return libcrun_configure_libkrun (args, err);

  return crun_make_error (err, EINVAL, "invalid handler specified `%s`", annotation);
}

static int
get_yajl_result (yajl_gen gen, char **out, size_t *out_len)
{
  const unsigned char *buf = NULL;
  size_t buf_len = 0;
  int r;

  r = yajl_gen_get_buf (gen, &buf, &buf_len);
  if (UNLIKELY (r != yajl_gen_status_ok))
    return r;

  *out_len = buf_len;

  *out = malloc (buf_len + 1);
  if (*out == NULL)
    OOM ();
  memcpy (*out, buf, buf_len);
  (*out)[buf_len] = '\0';

  return yajl_gen_status_ok;
}

static int
get_seccomp_receiver_fd_payload (libcrun_container_t *container, const char *status, pid_t own_pid,
                                 char **seccomp_fd_payload, size_t *seccomp_fd_payload_len, libcrun_error_t *err)
{
  int r;
  yajl_gen gen = NULL;
  runtime_spec_schema_config_schema *def = container->container_def;
  const char *const OCI_VERSION = "0.2.0";

  gen = yajl_gen_alloc (NULL);
  if (gen == NULL)
    return crun_make_error (err, 0, "yajl_gen_alloc failed");

  yajl_gen_config (gen, yajl_gen_beautify, 1);
  yajl_gen_config (gen, yajl_gen_validate_utf8, 1);

  r = yajl_gen_map_open (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_string (gen, YAJL_STR ("ociVersion"), strlen ("ociVersion"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_string (gen, YAJL_STR (OCI_VERSION), strlen (OCI_VERSION));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_string (gen, YAJL_STR ("fds"), strlen ("fds"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_array_open (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_string (gen, YAJL_STR ("seccompFd"), strlen ("seccompFd"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_array_close (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_string (gen, YAJL_STR ("pid"), strlen ("pid"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_integer (gen, own_pid);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  if (def && def->linux && def->linux->seccomp)
    {
      const char *metadata = def->linux->seccomp->listener_metadata;

      if (metadata)
        {
          r = yajl_gen_string (gen, YAJL_STR ("metadata"), strlen ("metadata"));
          if (UNLIKELY (r != yajl_gen_status_ok))
            goto exit;

          r = yajl_gen_string (gen, YAJL_STR (metadata), strlen (metadata));
          if (UNLIKELY (r != yajl_gen_status_ok))
            goto exit;
        }
    }

  /* State.  */
  r = yajl_gen_string (gen, YAJL_STR ("state"), strlen ("state"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_map_open (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_string (gen, YAJL_STR ("ociVersion"), strlen ("ociVersion"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_string (gen, YAJL_STR (OCI_VERSION), strlen (OCI_VERSION));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  if (container->context && container->context->id)
    {
      r = yajl_gen_string (gen, YAJL_STR ("id"), strlen ("id"));
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto exit;

      r = yajl_gen_string (gen, YAJL_STR (container->context->id), strlen (container->context->id));
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto exit;
    }

  r = yajl_gen_string (gen, YAJL_STR ("status"), strlen ("status"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_string (gen, YAJL_STR (status), strlen (status));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_string (gen, YAJL_STR ("pid"), strlen ("pid"));
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = yajl_gen_integer (gen, own_pid);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  if (container->context && container->context->bundle)
    {
      r = yajl_gen_string (gen, YAJL_STR ("bundle"), strlen ("bundle"));
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto exit;

      r = yajl_gen_string (gen, YAJL_STR (container->context->bundle), strlen (container->context->bundle));
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto exit;
    }

  if (def->annotations && def->annotations->len)
    {
      size_t i;

      r = yajl_gen_string (gen, YAJL_STR ("annotations"), strlen ("annotations"));
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto exit;

      r = yajl_gen_map_open (gen);
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto exit;

      for (i = 0; i < def->annotations->len; i++)
        {
          const char *key = def->annotations->keys[i];
          const char *val = def->annotations->values[i];

          r = yajl_gen_string (gen, YAJL_STR (key), strlen (key));
          if (UNLIKELY (r != yajl_gen_status_ok))
            goto exit;

          r = yajl_gen_string (gen, YAJL_STR (val), strlen (val));
          if (UNLIKELY (r != yajl_gen_status_ok))
            goto exit;
        }
      r = yajl_gen_map_close (gen);
      if (UNLIKELY (r != yajl_gen_status_ok))
        goto exit;
    }

  r = yajl_gen_map_close (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;
  /* End state.  */

  r = yajl_gen_map_close (gen);
  if (UNLIKELY (r != yajl_gen_status_ok))
    goto exit;

  r = get_yajl_result (gen, seccomp_fd_payload, seccomp_fd_payload_len);

exit:
  yajl_gen_free (gen);

  return yajl_error_to_crun_error (r, err);
}

static int
send_sync_cb (void *data, libcrun_error_t *err)
{
  int sync_socket_fd = *((int *) data);
  int ret;

  /* sync 2.  */
  ret = sync_socket_send_sync (sync_socket_fd, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* sync 3.  */
  return sync_socket_wait_sync (NULL, sync_socket_fd, false, err);
}

/* Initialize the environment where the container process runs.
   It is used by the container init process.  */
static int
container_init_setup (void *args, pid_t own_pid, char *notify_socket, int sync_socket, const char **exec_path, libcrun_error_t *err)
{
  struct container_entrypoint_s *entrypoint_args = args;
  libcrun_container_t *container = entrypoint_args->container;
  int ret;
  int has_terminal;
  cleanup_close int console_socket = -1;
  cleanup_close int console_socketpair = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  runtime_spec_schema_config_schema_process_capabilities *capabilities;
  cleanup_free char *rootfs = NULL;
  int no_new_privs;

  ret = libcrun_configure_handler (args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = initialize_security (def->process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_configure_network (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->root && def->root->path)
    {
      rootfs = realpath (def->root->path, NULL);
      if (UNLIKELY (rootfs == NULL))
        {
          /* If realpath failed for any reason, try the relative directory.  */
          rootfs = xstrdup (def->root->path);
        }
    }

  if (entrypoint_args->terminal_socketpair[0] >= 0)
    {
      close_and_reset (&entrypoint_args->terminal_socketpair[0]);
      console_socketpair = entrypoint_args->terminal_socketpair[1];
    }

  /* sync 1.  */
  ret = sync_socket_wait_sync (NULL, sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  has_terminal = container->container_def->process && container->container_def->process->terminal;
  if (has_terminal && entrypoint_args->context->console_socket)
    console_socket = entrypoint_args->console_socket_fd;

  ret = libcrun_set_sysctl (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* sync 2 and 3 are sent as part of libcrun_set_mounts.  */
  ret = libcrun_set_mounts (container, rootfs, send_sync_cb, &sync_socket, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->hooks && def->hooks->create_container_len)
    {
      ret = do_hooks (def, 0, container->context->id, false, NULL, "created", (hook **) def->hooks->create_container,
                      def->hooks->create_container_len, entrypoint_args->hooks_out_fd, entrypoint_args->hooks_err_fd,
                      err);
      if (UNLIKELY (ret != 0))
        return ret;
    }

  if (def->process)
    {
      ret = libcrun_set_selinux_exec_label (def->process, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcrun_set_apparmor_profile (def->process, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = mark_for_close_fds_ge_than (entrypoint_args->context->preserve_fds + 3, err);
  if (UNLIKELY (ret < 0))
    crun_error_write_warning_and_release (entrypoint_args->context->output_handler_arg, &err);

  if (rootfs)
    {
      ret = libcrun_do_pivot_root (container, entrypoint_args->context->no_pivot, rootfs, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_reopen_dev_null (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (clearenv ())
    return crun_make_error (err, errno, "clearenv");

  if (def->process)
    {
      size_t i;

      for (i = 0; i < def->process->env_len; i++)
        if (putenv (def->process->env[i]) < 0)
          return crun_make_error (err, errno, "putenv `%s`", def->process->env[i]);
    }

  if (getenv ("HOME") == NULL)
    {
      ret = set_home_env (container->container_uid);
      if (UNLIKELY (ret < 0 && errno != ENOTSUP))
        {
          setenv ("HOME", "/", 1);
          libcrun_warning ("cannot detect HOME environment variable, setting default");
        }
    }

  if (def->process && def->process->cwd)
    if (UNLIKELY (chdir (def->process->cwd) < 0))
      return crun_make_error (err, errno, "chdir");

  if (def->process && def->process->args)
    {
      *exec_path = find_executable (def->process->args[0], def->process->cwd);
      if (UNLIKELY (*exec_path == NULL))
        {
          if (errno == ENOENT)
            return crun_make_error (err, errno, "executable file `%s` not found in $PATH", def->process->args[0]);

          return crun_make_error (err, errno, "open executable");
        }
      if (entrypoint_args->context->kontain)
        {
          int rc = libcrun_kontain_argv (&def->process->args, exec_path);
          if (rc != 0)
            {
              return crun_make_error (err, rc, "init: fixup argv");
            }
        }
    }

  ret = setsid ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "setsid");

  if (has_terminal)
    {
      cleanup_close int terminal_fd = -1;

      fflush (stderr);

      terminal_fd = libcrun_set_terminal (container, err);
      if (UNLIKELY (terminal_fd < 0))
        return terminal_fd;

      if (console_socket >= 0)
        {
          ret = send_fd_to_socket (console_socket, terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close_and_reset (&console_socket);
        }
      else if (entrypoint_args->has_terminal_socket_pair && console_socketpair >= 0)
        {
          ret = send_fd_to_socket (console_socketpair, terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;

          close_and_reset (&console_socketpair);
        }
    }

  ret = libcrun_set_hostname (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->container_def->linux && container->container_def->linux->personality)
    {
      ret = libcrun_set_personality (container->container_def->linux->personality, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (def->process && def->process->user)
    umask (def->process->user->umask_present ? def->process->user->umask : 0022);

  if (def->process && ! def->process->no_new_privileges)
    {
      char **seccomp_flags = NULL;
      size_t seccomp_flags_len = 0;
      cleanup_free char *seccomp_fd_payload = NULL;
      size_t seccomp_fd_payload_len = 0;

      if (def->linux && def->linux->seccomp)
        {
          seccomp_flags = def->linux->seccomp->flags;
          seccomp_flags_len = def->linux->seccomp->flags_len;
        }

      if (entrypoint_args->seccomp_receiver_fd >= 0)
        {
          ret = get_seccomp_receiver_fd_payload (container, "creating", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = libcrun_apply_seccomp (entrypoint_args->seccomp_fd, entrypoint_args->seccomp_receiver_fd,
                                   seccomp_fd_payload, seccomp_fd_payload_len, seccomp_flags, seccomp_flags_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      close_and_reset (&entrypoint_args->seccomp_fd);
      close_and_reset (&entrypoint_args->seccomp_receiver_fd);
    }

  if (entrypoint_args->container->use_intermediate_userns)
    {
      ret = libcrun_create_final_userns (entrypoint_args->container, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  capabilities = def->process ? def->process->capabilities : NULL;
  no_new_privs = def->process ? def->process->no_new_privileges : 1;
  ret = libcrun_set_caps (capabilities, container->container_uid, container->container_gid, no_new_privs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (notify_socket)
    {
      if (putenv (notify_socket) < 0)
        return crun_make_error (err, errno, "putenv `%s`", notify_socket);
    }

  return 0;
}

static int
open_hooks_output (libcrun_container_t *container, int *out_fd, int *err_fd, libcrun_error_t *err)
{
  const char *annotation;

  *err_fd = *out_fd = -1;

  annotation = find_annotation (container, "run.oci.hooks.stdout");
  if (annotation)
    {
      *out_fd = TEMP_FAILURE_RETRY (open (annotation, O_CREAT | O_WRONLY | O_APPEND, 0700));
      if (UNLIKELY (*out_fd < 0))
        return crun_make_error (err, errno, "open `%s`", annotation);
    }

  annotation = find_annotation (container, "run.oci.hooks.stderr");
  if (annotation)
    {
      *err_fd = TEMP_FAILURE_RETRY (open (annotation, O_CREAT | O_WRONLY | O_APPEND, 0700));
      if (UNLIKELY (*err_fd < 0))
        return crun_make_error (err, errno, "open `%s`", annotation);
    }

  return 0;
}

/* Entrypoint to the container.  */
static int
container_init (void *args, char *notify_socket, int sync_socket, libcrun_error_t *err)
{
  struct container_entrypoint_s *entrypoint_args = args;
  int ret;
  runtime_spec_schema_config_schema *def = entrypoint_args->container->container_def;
  cleanup_free const char *exec_path = NULL;
  __attribute__ ((unused)) cleanup_free char *notify_socket_cleanup = notify_socket;
  pid_t own_pid = 0;

  entrypoint_args->sync_socket = sync_socket;

  crun_set_output_handler (log_write_to_sync_socket, args, false);

  /* sync receive own pid.  */
  ret = TEMP_FAILURE_RETRY (read (sync_socket, &own_pid, sizeof (own_pid)));
  if (UNLIKELY (ret != sizeof (own_pid)))
    {
      if (ret >= 0)
        errno = 0;
      return crun_make_error (err, errno, "read from sync socket");
    }

  ret = container_init_setup (args, own_pid, notify_socket, sync_socket, &exec_path, err);
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

  ret = unblock_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* sync 4.  */
  ret = sync_socket_send_sync (sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  close_and_reset (&sync_socket);

  if (entrypoint_args->context->fifo_exec_wait_fd >= 0)
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
      } while (ret == 0);

      close_and_reset (&entrypoint_args->context->fifo_exec_wait_fd);
    }

  crun_set_output_handler (log_write_to_stderr, NULL, false);

  if (def->process && def->process->no_new_privileges)
    {
      char **seccomp_flags = NULL;
      size_t seccomp_flags_len = 0;
      cleanup_free char *seccomp_fd_payload = NULL;
      size_t seccomp_fd_payload_len = 0;

      if (def->linux && def->linux->seccomp)
        {
          seccomp_flags = def->linux->seccomp->flags;
          seccomp_flags_len = def->linux->seccomp->flags_len;
        }

      if (entrypoint_args->seccomp_receiver_fd >= 0)
        {
          ret = get_seccomp_receiver_fd_payload (entrypoint_args->container, "creating", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = libcrun_apply_seccomp (entrypoint_args->seccomp_fd, entrypoint_args->seccomp_receiver_fd,
                                   seccomp_fd_payload, seccomp_fd_payload_len, seccomp_flags,
                                   seccomp_flags_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
      close_and_reset (&entrypoint_args->seccomp_fd);
      close_and_reset (&entrypoint_args->seccomp_receiver_fd);
    }

  if (UNLIKELY (def->process == NULL))
    return crun_make_error (err, 0, "block 'process' not found");

  if (UNLIKELY (exec_path == NULL))
    return crun_make_error (err, 0, "executable path not specified");

  if (def->hooks && def->hooks->start_container_len)
    {
      libcrun_container_t *container = entrypoint_args->container;

      ret = do_hooks (def, 0, container->context->id, false, NULL, "starting", (hook **) def->hooks->start_container,
                      def->hooks->start_container_len, entrypoint_args->hooks_out_fd, entrypoint_args->hooks_err_fd,
                      err);
      if (UNLIKELY (ret != 0))
        return ret;

      /* Seek stdout/stderr to the end.  If the hooks were using the same files,
         the container process overwrites what was previously written.  */
      (void) lseek (1, 0, SEEK_END);
      (void) lseek (2, 0, SEEK_END);
    }

  if (entrypoint_args->exec_func)
    {
      ret = entrypoint_args->exec_func (entrypoint_args->container, entrypoint_args->exec_func_arg, exec_path,
                                        def->process->args);
      _exit (ret);
    }

  execv (exec_path, def->process->args);

  if (errno == ENOENT)
    return crun_make_error (err, errno, "exec container process (missing dynamic library?) `%s`", exec_path);

  return crun_make_error (err, errno, "exec container process `%s`", exec_path);
}

static int
read_container_config_from_state (libcrun_container_t **container, const char *state_root, const char *id,
                                  libcrun_error_t *err)
{
  cleanup_free char *config_file = NULL;
  cleanup_free char *dir = NULL;
  int ret;

  *container = NULL;

  dir = libcrun_get_state_directory (state_root, id);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, 0, "cannot get state directory from `%s`", state_root);

  ret = append_paths (&config_file, err, dir, "config.json", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  *container = libcrun_container_load_from_file (config_file, err);
  if (*container == NULL)
    return crun_make_error (err, 0, "error loading `%s`", config_file);

  return 0;
}

static int
run_poststop_hooks (libcrun_context_t *context, libcrun_container_t *container, runtime_spec_schema_config_schema *def,
                    libcrun_container_status_t *status, const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_container libcrun_container_t *container_cleanup = NULL;
  int ret;

  if (def == NULL)
    {
      if (container == NULL)
        {
          ret = read_container_config_from_state (&container_cleanup, state_root, id, err);
          if (UNLIKELY (ret < 0))
            return ret;
          container = container_cleanup;
        }

      def = container->container_def;
    }

  if (def->hooks && def->hooks->poststop_len)
    {
      cleanup_close int hooks_out_fd = -1;
      cleanup_close int hooks_err_fd = -1;

      if (container == NULL)
        {
          ret = read_container_config_from_state (&container_cleanup, state_root, id, err);
          if (UNLIKELY (ret < 0))
            return ret;
          container = container_cleanup;
        }

      ret = open_hooks_output (container, &hooks_out_fd, &hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = do_hooks (def, 0, id, true, status->bundle, "stopped", (hook **) def->hooks->poststop,
                      def->hooks->poststop_len, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        crun_error_write_warning_and_release (context->output_handler_arg, &err);
    }
  return 0;
}

static bool
has_new_pid_namespace (runtime_spec_schema_config_schema *def)
{
  size_t i;

  if (def->linux == NULL || def->linux->namespaces == NULL)
    return false;

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      if (strcmp (def->linux->namespaces[i]->type, "pid") == 0 && def->linux->namespaces[i]->path == NULL)
        return true;
    }
  return false;
}

static int
container_delete_internal (libcrun_context_t *context, runtime_spec_schema_config_schema *def, const char *id,
                           bool force, bool killall, libcrun_error_t *err)
{
  int ret;
  cleanup_container_status libcrun_container_status_t status = {};
  const char *state_root = context->state_root;
  cleanup_container libcrun_container_t *container = NULL;

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
      return libcrun_container_delete_status (state_root, id, err);
    }

  if (! force)
    {
      ret = libcrun_is_container_running (&status, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret == 1)
        return crun_make_error (err, 0, "the container `%s` is not in 'stopped' state", id);
    }

  if (killall)
    {
      if (force)
        {
          if (def == NULL)
            {
              ret = read_container_config_from_state (&container, state_root, id, err);
              if (UNLIKELY (ret < 0))
                return ret;

              def = container->container_def;
            }

          /* If the container has a pid namespace, it is enough to kill the first
             process (pid=1 in the namespace).
          */
          if (has_new_pid_namespace (def))
            {
              ret = libcrun_kill_linux (&status, SIGKILL, err);
              if (UNLIKELY (ret < 0))
                {
                  if (crun_error_get_errno (err) != ESRCH)
                    return ret;

                  crun_error_release (err);
                }
            }
          else if (status.cgroup_path)
            {
              ret = libcrun_cgroup_killall (status.cgroup_path, err);
              if (UNLIKELY (ret < 0))
                return 0;
            }
        }
    }

  if (status.cgroup_path)
    {
      int manager;

      manager = status.systemd_cgroup ? CGROUP_MANAGER_SYSTEMD : CGROUP_MANAGER_CGROUPFS;
      ret = libcrun_cgroup_destroy (id, status.cgroup_path, status.scope, manager, err);
      if (UNLIKELY (ret < 0))
        crun_error_write_warning_and_release (context->output_handler_arg, &err);
    }

  ret = run_poststop_hooks (context, container, def, &status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    crun_error_write_warning_and_release (context->output_handler_arg, &err);

  return libcrun_container_delete_status (state_root, id, err);
}

int
libcrun_container_delete (libcrun_context_t *context, runtime_spec_schema_config_schema *def, const char *id,
                          bool force, libcrun_error_t *err)
{
  return container_delete_internal (context, def, id, force, true, err);
}

int
libcrun_container_kill (libcrun_context_t *context, const char *id, int signal, libcrun_error_t *err)
{
  int ret;
  const char *state_root = context->state_root;
  cleanup_container_status libcrun_container_status_t status = {};

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return libcrun_kill_linux (&status, signal, err);
}

int
libcrun_container_kill_all (libcrun_context_t *context, const char *id, int signal, libcrun_error_t *err)
{
  int ret;
  const char *state_root = context->state_root;
  cleanup_container_status libcrun_container_status_t status = {};

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_cgroup_killall_signal (status.cgroup_path, signal, err);
  if (UNLIKELY (ret < 0))
    return ret;
  return 0;
}

static int
write_container_status (libcrun_container_t *container, libcrun_context_t *context, pid_t pid, char *cgroup_path,
                        char *scope, char *created, libcrun_error_t *err)
{
  cleanup_free char *cwd = getcwd (NULL, 0);
  cleanup_free char *owner = get_user_name (geteuid ());
  char *external_descriptors = libcrun_get_external_descriptors (container);
  char *rootfs = container->container_def->root ? container->container_def->root->path : "";
  libcrun_container_status_t status = { .pid = pid,
                                        .cgroup_path = cgroup_path,
                                        .scope = scope,
                                        .rootfs = rootfs,
                                        .bundle = cwd,
                                        .created = created,
                                        .owner = owner,
                                        .systemd_cgroup = context->systemd_cgroup,
                                        .detached = context->detach,
                                        .external_descriptors = external_descriptors };
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
handle_notify_socket (int notify_socketfd, libcrun_error_t *err)
{
#ifdef HAVE_SYSTEMD
  int ret;
  char buf[256];
  const char *ready_str = "READY=1";

  ret = recvfrom (notify_socketfd, buf, sizeof (buf) - 1, 0, NULL, NULL);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "recvfrom notify socket");

  buf[ret] = '\0';
  if (strstr (buf, ready_str))
    {
      ret = sd_notify (0, ready_str);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "sd_notify");

      return 1;
    }
  return 0;
#else
  (void) notify_socketfd;
  (void) err;
  return 1;
#endif
}

static int
wait_for_process (pid_t pid, libcrun_context_t *context, int terminal_fd, int notify_socket, int container_ready_fd,
                  int seccomp_notify_fd, const char *seccomp_notify_plugins, libcrun_error_t *err)
{
  cleanup_close int epollfd = -1;
  cleanup_close int signalfd = -1;
  int ret, container_exit_code = 0, last_process;
  sigset_t mask;
  int fds[10];
  int levelfds[10];
  int levelfds_len = 0;
  int fds_len = 0;
  cleanup_seccomp_notify_context struct seccomp_notify_context_s *seccomp_notify_ctx = NULL;

  container_exit_code = 0;

  if (context->pid_file)
    {
      char buf[12];
      size_t buf_len = sprintf (buf, "%d", pid);
      ret = write_file_with_flags (context->pid_file, O_CREAT | O_TRUNC, buf, buf_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Also exit if there is nothing more to wait for.  */
  if (context->detach && notify_socket < 0)
    return 0;

  if (container_ready_fd >= 0)
    {
      ret = 0;
      TEMP_FAILURE_RETRY (write (container_ready_fd, &ret, sizeof (ret)));
      close_and_reset (&container_ready_fd);
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

  if (seccomp_notify_fd >= 0)
    {
      cleanup_free char *state_root = NULL;
      cleanup_free char *oci_config_path = NULL;

      struct libcrun_load_seccomp_notify_conf_s conf;
      memset (&conf, 0, sizeof conf);

      state_root = libcrun_get_state_directory (context->state_root, context->id);
      if (UNLIKELY (state_root == NULL))
        return crun_make_error (err, 0, "cannot get state directory");

      ret = append_paths (&oci_config_path, err, state_root, "config.json", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      conf.runtime_root_path = state_root;
      conf.name = context->id;
      conf.bundle_path = context->bundle;
      conf.oci_config_path = oci_config_path;

      ret = set_blocking_fd (seccomp_notify_fd, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcrun_load_seccomp_notify_plugins (&seccomp_notify_ctx, seccomp_notify_plugins, &conf, err);
      if (UNLIKELY (ret < 0))
        return ret;

      fds[fds_len++] = seccomp_notify_fd;
    }

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
                return crun_error_wrap (err, "copy to terminal fd");
            }
          else if (events[i].data.fd == seccomp_notify_fd)
            {
              ret = libcrun_seccomp_notify_plugins (seccomp_notify_ctx, seccomp_notify_fd, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
          else if (events[i].data.fd == terminal_fd)
            {
              ret = set_blocking_fd (terminal_fd, 0, err);
              if (UNLIKELY (ret < 0))
                return crun_error_wrap (err, "set terminal fd not blocking");

              ret = copy_from_fd_to_fd (terminal_fd, 1, 1, err);
              if (UNLIKELY (ret < 0))
                return crun_error_wrap (err, "copy from terminal fd");

              ret = set_blocking_fd (terminal_fd, 1, err);
              if (UNLIKELY (ret < 0))
                return crun_error_wrap (err, "set terminal fd blocking");
            }
          else if (events[i].data.fd == notify_socket)
            {
              ret = handle_notify_socket (notify_socket, err);
              if (UNLIKELY (ret < 0))
                return ret;
              if (ret && context->detach)
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
flush_fd_to_err (libcrun_context_t *context, int terminal_fd)
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
      int ret = TEMP_FAILURE_RETRY (read (terminal_fd, buf, sizeof (buf) - 1));
      if (ret <= 0)
        break;
      buf[ret] = '\0';
      if (context->output_handler)
        context->output_handler (0, buf, false, context->output_handler_arg);
    }
  (void) fcntl (terminal_fd, F_SETFL, flags);
  fflush (stderr);
  fsync (1);
  fsync (2);
}

static int
cleanup_watch (libcrun_context_t *context, runtime_spec_schema_config_schema *def, const char *cgroup_path, int cgroup_mode, pid_t init_pid, int sync_socket, int terminal_fd, libcrun_error_t *err)
{
  const char *oom_message = NULL;
  libcrun_error_t tmp_err = NULL;
  int ret;

  if (init_pid)
    {
      /* Try to detect whether the cgroup has a OOM.  */
      if (cgroup_path != NULL && cgroup_path[0])
        {
          int has_oom;

          has_oom = libcrun_cgroup_has_oom (cgroup_path, cgroup_mode, &tmp_err);
          if (has_oom > 0)
            oom_message = "OOM: the memory limit could be too low";
          else if (has_oom < 0)
            {
              /* If the detection has failed for any reason, e.g. the cgroup was
                 already deleted by the time it was checked, just ignore the
                 failure.  */
              crun_error_release (&tmp_err);
            }
        }
      /* If the OOM wasn't detected, look into the static configuration.  */
      if (oom_message == NULL && is_memory_limit_too_low (def))
        oom_message = "the memory limit could be too low";

      kill (init_pid, SIGKILL);
      TEMP_FAILURE_RETRY (waitpid (init_pid, NULL, 0));
    }

  ret = sync_socket_wait_sync (context, sync_socket, true, &tmp_err);
  if (UNLIKELY (ret < 0))
    {
      crun_error_release (err);
      *err = tmp_err;
    }

  if (terminal_fd >= 0)
    flush_fd_to_err (context, terminal_fd);

  if (oom_message)
    return crun_error_wrap (err, "%s", oom_message);

  return -1;
}

static int
open_seccomp_output (const char *id, int *fd, bool readonly, const char *state_root, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *dest_path = NULL;
  cleanup_free char *dir = NULL;

  dir = libcrun_get_state_directory (state_root, id);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, 0, "cannot get state directory");

  ret = append_paths (&dest_path, err, dir, "seccomp.bpf", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  *fd = -1;
  if (readonly)
    {
      ret = TEMP_FAILURE_RETRY (open (dest_path, O_RDONLY));
      if (UNLIKELY (ret < 0))
        {
          if (errno == ENOENT)
            return 0;
          return crun_make_error (err, errno, "open seccomp.bpf");
        }
      *fd = ret;
    }
  else
    {
      ret = TEMP_FAILURE_RETRY (open (dest_path, O_RDWR | O_CREAT, 0700));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "open seccomp.bpf");
      *fd = ret;
    }

  return 0;
}

/* Find the uid:gid that is mapped to root inside the container user namespace.  */
void
get_root_in_the_userns (runtime_spec_schema_config_schema *def, uid_t host_uid, gid_t host_gid, uid_t *uid,
                        gid_t *gid)
{
  *uid = -1;
  *gid = -1;

  /* Not root in the namespace.  */
  if (host_uid)
    return;

  if (def->linux && def->linux->uid_mappings)
    {
      size_t i;

      for (i = 0; i < def->linux->uid_mappings_len; i++)
        if (def->linux->uid_mappings[i]->container_id == 0)
          {
            *uid = def->linux->uid_mappings[i]->host_id;
            break;
          }
    }
  if (def->linux && def->linux->gid_mappings)
    {
      size_t i;

      for (i = 0; i < def->linux->gid_mappings_len; i++)
        if (def->linux->gid_mappings[i]->container_id == 0)
          {
            *gid = def->linux->gid_mappings[i]->host_id;
            break;
          }
    }

  /* If the uid and the gid are not changed, do not attempt any chown.  */
  if (*uid == host_uid && *gid == host_gid)
    *uid = *gid = -1;
}

static const char *
find_delegate_cgroup (libcrun_container_t *container)
{
  const char *annotation;

  annotation = find_annotation (container, "run.oci.delegate-cgroup");
  if (annotation)
    {
      if (annotation[0] == '\0')
        return NULL;
      return annotation;
    }

  return NULL;
}

static const char *
find_systemd_subgroup (libcrun_container_t *container, int cgroup_mode)
{
  const char *annotation;

  annotation = find_annotation (container, "run.oci.systemd.subgroup");
  if (annotation)
    {
      if (annotation[0] == '\0')
        return NULL;
      return annotation;
    }

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    return "container";

  return NULL;
}

static int
get_seccomp_receiver_fd (libcrun_container_t *container, int *fd, int *self_receiver_fd, const char **plugins,
                         libcrun_error_t *err)
{
  const char *tmp;
  runtime_spec_schema_config_schema *def = container->container_def;

  *fd = -1;
  *self_receiver_fd = -1;

  tmp = find_annotation (container, "run.oci.seccomp.plugins");
  if (tmp)
    {
      int fds[2];
      int ret;

      ret = create_socket_pair (fds, err);
      if (UNLIKELY (ret < 0))
        return crun_error_wrap (err, "create socket pair");

      *fd = fds[0];
      *self_receiver_fd = fds[1];
      *plugins = tmp;
    }

  if (def && def->linux && def->linux->seccomp && def->linux->seccomp->listener_path)
    tmp = def->linux->seccomp->listener_path;
  else
    tmp = find_annotation (container, "run.oci.seccomp.receiver");
  if (tmp == NULL)
    tmp = getenv ("RUN_OCI_SECCOMP_RECEIVER");
  if (tmp)
    {
      if (tmp[0] != '/')
        return crun_make_error (err, 0, "the seccomp receiver `%s` is not an absolute path", tmp);

      *fd = open_unix_domain_client_socket (tmp, 0, err);
      if (UNLIKELY (*fd < 0))
        return crun_error_wrap (err, "open seccomp receiver");
    }

  return 0;
}

static int
libcrun_container_run_internal (libcrun_container_t *container, libcrun_context_t *context, int container_ready_fd,
                                libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;
  pid_t pid;
  int detach = context->detach;
  cleanup_free char *cgroup_path = NULL;
  cleanup_free char *scope = NULL;
  cleanup_close int terminal_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_close int sync_socket = -1;
  cleanup_close int notify_socket = -1;
  cleanup_close int socket_pair_0 = -1;
  cleanup_close int socket_pair_1 = -1;
  cleanup_close int seccomp_fd = -1;
  cleanup_close int console_socket_fd = -1;
  cleanup_close int hooks_out_fd = -1;
  cleanup_close int hooks_err_fd = -1;
  cleanup_close int own_seccomp_receiver_fd = -1;
  cleanup_close int seccomp_notify_fd = -1;
  const char *seccomp_notify_plugins = NULL;
  int cgroup_mode, cgroup_manager;
  char created[35];
  uid_t root_uid = -1;
  gid_t root_gid = -1;
  struct container_entrypoint_s container_args = {
    .container = container,
    .context = context,
    .terminal_socketpair = { -1, -1 },
    .console_socket_fd = -1,
    .hooks_out_fd = -1,
    .hooks_err_fd = -1,
    .seccomp_receiver_fd = -1,
    .exec_func = context->exec_func,
    .exec_func_arg = context->exec_func_arg,
  };

  if (def->hooks
      && (def->hooks->prestart_len || def->hooks->poststart_len || def->hooks->create_runtime_len
          || def->hooks->create_container_len || def->hooks->start_container_len))
    {
      ret = open_hooks_output (container, &hooks_out_fd, &hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
      container_args.hooks_out_fd = hooks_out_fd;
      container_args.hooks_err_fd = hooks_err_fd;
    }

  container->context = context;

  if (! detach || context->notify_socket)
    {
      ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "set child subreaper");
    }

  if (! context->no_new_keyring)
    {
      const char *label = NULL;

      if (def->process)
        label = def->process->selinux_label;

      ret = libcrun_create_keyring (container->context->id, label, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (def->process && def->process->terminal && ! detach && context->console_socket == NULL)
    {
      container_args.has_terminal_socket_pair = 1;
      ret = create_socket_pair (container_args.terminal_socketpair, err);
      if (UNLIKELY (ret < 0))
        return crun_error_wrap (err, "create terminal socket");

      socket_pair_0 = container_args.terminal_socketpair[0];
      socket_pair_1 = container_args.terminal_socketpair[1];
    }

  ret = block_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->linux && (def->linux->seccomp || find_annotation (container, "run.oci.seccomp_bpf_data")))
    {
      ret = open_seccomp_output (context->id, &seccomp_fd, false, context->state_root, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  container_args.seccomp_fd = seccomp_fd;

  if (seccomp_fd >= 0)
    {
      ret = get_seccomp_receiver_fd (container, &container_args.seccomp_receiver_fd, &own_seccomp_receiver_fd,
                                     &seccomp_notify_plugins, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (context->console_socket)
    {
      console_socket_fd = open_unix_domain_client_socket (context->console_socket, 0, err);
      if (UNLIKELY (console_socket_fd < 0))
        return crun_error_wrap (err, "open console socket");
      container_args.console_socket_fd = console_socket_fd;
    }

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  pid = libcrun_run_linux_container (container, container_init, &container_args, &sync_socket, err);
  if (UNLIKELY (pid < 0))
    return pid;

  if (context->fifo_exec_wait_fd < 0 && context->notify_socket)
    {
      /* Do not open the notify socket here on "create".  "start" will take care of it.  */
      ret = get_notify_fd (context, container, &notify_socket, err);
      if (UNLIKELY (ret < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  if (container_args.terminal_socketpair[1] >= 0)
    close_and_reset (&socket_pair_1);

  cgroup_manager = CGROUP_MANAGER_CGROUPFS;
  if (context->systemd_cgroup)
    cgroup_manager = CGROUP_MANAGER_SYSTEMD;
  else if (context->force_no_cgroup)
    cgroup_manager = CGROUP_MANAGER_DISABLED;

  /* If we are root (either on the host or in a namespace), then chown the cgroup to root in the container user
   * namespace.  */
  get_root_in_the_userns (def, container->host_uid, container->host_gid, &root_uid, &root_gid);

  {
    struct libcrun_cgroup_args cg = {
      .resources = def->linux ? def->linux->resources : NULL,
      .annotations = def->annotations,
      .cgroup_mode = cgroup_mode,
      .path = &cgroup_path,
      .scope = &scope,
      .cgroup_path = def->linux ? def->linux->cgroups_path : "",
      .manager = cgroup_manager,
      .pid = pid,
      .root_uid = root_uid,
      .root_gid = root_gid,
      .id = context->id,
      .systemd_subgroup = find_systemd_subgroup (container, cgroup_mode),
      .delegate_cgroup = find_delegate_cgroup (container),
    };

    ret = libcrun_cgroup_enter (&cg, err);
    if (UNLIKELY (ret < 0))
      return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
  }

  /* sync send own pid.  */
  ret = TEMP_FAILURE_RETRY (write (sync_socket, &pid, sizeof (pid)));
  if (UNLIKELY (ret != sizeof (pid)))
    {
      if (ret >= 0)
        errno = 0;
      crun_make_error (err, errno, "write to sync socket");
      return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  /* sync 1.  */
  ret = sync_socket_send_sync (sync_socket, true, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  /* sync 2.  */
  ret = sync_socket_wait_sync (context, sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  /* The container is waiting that we write back.  In this phase we can launch the
     prestart hooks.  */
  if (def->hooks && def->hooks->prestart_len)
    {
      ret = do_hooks (def, pid, context->id, false, NULL, "created", (hook **) def->hooks->prestart,
                      def->hooks->prestart_len, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret != 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }
  if (def->hooks && def->hooks->create_runtime_len)
    {
      ret = do_hooks (def, pid, context->id, false, NULL, "created", (hook **) def->hooks->create_runtime,
                      def->hooks->create_runtime_len, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret != 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  if (seccomp_fd >= 0)
    {
      unsigned int seccomp_gen_options = 0;
      const char *annotation;

      annotation = find_annotation (container, "run.oci.seccomp_fail_unknown_syscall");
      if (annotation && strcmp (annotation, "0") != 0)
        seccomp_gen_options = LIBCRUN_SECCOMP_FAIL_UNKNOWN_SYSCALL;

      if ((annotation = find_annotation (container, "run.oci.seccomp_bpf_data")) != NULL)
        {
          cleanup_free char *bpf_data = NULL;
          size_t size = 0;
          size_t in_size;
          int consumed;

          in_size = strlen (annotation);
          bpf_data = xmalloc (in_size + 1);

          consumed = base64_decode (annotation, in_size, bpf_data, in_size, &size);
          if (UNLIKELY (consumed != (int) in_size))
            {
              ret = crun_make_error (err, 0, "invalid seccomp BPF data");
              return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
            }

          ret = safe_write (seccomp_fd, bpf_data, (ssize_t) size);
          if (UNLIKELY (ret < 0))
            {
              crun_make_error (err, 0, "write to seccomp fd");
              return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
            }
        }
      else
        {
          ret = libcrun_generate_seccomp (container, seccomp_fd, seccomp_gen_options, err);
          if (UNLIKELY (ret < 0))
            return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
        }
      close_and_reset (&seccomp_fd);
    }

  /* sync 3.  */
  ret = sync_socket_send_sync (sync_socket, true, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  if (def->process && def->process->terminal && ! detach && context->console_socket == NULL)
    {
      terminal_fd = receive_fd_from_socket (socket_pair_0, err);
      if (UNLIKELY (terminal_fd < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

      close_and_reset (&socket_pair_0);

      ret = libcrun_setup_terminal_ptmx (terminal_fd, &orig_terminal, err);
      if (UNLIKELY (ret < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  /* sync 4.  */
  ret = sync_socket_wait_sync (context, sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  ret = close_and_reset (&sync_socket);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  get_current_timestamp (created);
  ret = write_container_status (container, context, pid, cgroup_path, scope, created, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  /* Run poststart hooks here only if the container is created using "run".  For create+start, the
     hooks will be executed as part of the start command.  */
  if (context->fifo_exec_wait_fd < 0 && def->hooks && def->hooks->poststart_len)
    {
      ret = do_hooks (def, pid, context->id, true, NULL, "running", (hook **) def->hooks->poststart,
                      def->hooks->poststart_len, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  /* Let's receive the seccomp notify fd and handle it as part of wait_for_process().  */
  if (own_seccomp_receiver_fd >= 0)
    {
      seccomp_notify_fd = receive_fd_from_socket (own_seccomp_receiver_fd, err);
      if (UNLIKELY (seccomp_notify_fd < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

      ret = close_and_reset (&own_seccomp_receiver_fd);
      if (UNLIKELY (ret < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  ret = wait_for_process (pid, context, terminal_fd, notify_socket, container_ready_fd, seccomp_notify_fd,
                          seccomp_notify_plugins, err);
  if (! context->detach)
    {
      libcrun_error_t tmp_err = NULL;
      cleanup_watch (context, def, cgroup_path, cgroup_mode, 0, sync_socket, terminal_fd, &tmp_err);
      crun_error_release (&tmp_err);
    }

  return ret;
}

static int
check_config_file (runtime_spec_schema_config_schema *def, libcrun_context_t *context, libcrun_error_t *err)
{
  if (UNLIKELY (def->linux == NULL))
    return crun_make_error (err, 0, "invalid config file, no 'linux' block specified");
  if (context->exec_func == NULL)
    {
      if (UNLIKELY (def->root == NULL))
        return crun_make_error (err, 0, "invalid config file, no 'root' block specified");
      if (UNLIKELY (def->mounts == NULL))
        return crun_make_error (err, 0, "invalid config file, no 'mounts' block specified");
    }
  return 0;
}

static int
libcrun_copy_config_file (const char *id, const char *state_root, const char *config_file, const char *config_file_content, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *dest_path = NULL;
  cleanup_free char *dir = NULL;
  cleanup_free char *buffer = NULL;
  size_t len;

  dir = libcrun_get_state_directory (state_root, id);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, 0, "cannot get state directory");

  ret = append_paths (&dest_path, err, dir, "config.json", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  if (config_file == NULL && config_file_content == NULL)
    return crun_make_error (err, 0, "config file not specified");

  if (config_file == NULL)
    {
      ret = write_file (dest_path, config_file_content, strlen (config_file_content), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = read_all_file (config_file, &buffer, &len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_file (dest_path, buffer, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static void
force_delete_container_status (libcrun_context_t *context, runtime_spec_schema_config_schema *def)
{
  libcrun_error_t tmp_err = NULL;
  container_delete_internal (context, def, context->id, true, false, &tmp_err);
  crun_error_release (&tmp_err);
}

int
libcrun_container_run (libcrun_context_t *context, libcrun_container_t *container, unsigned int options,
                       libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;
  int detach = context->detach;
  int container_ret_status[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  libcrun_error_t tmp_err = NULL;

  container->context = context;

  ret = check_config_file (def, context, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->oci_version && strstr (def->oci_version, "1.0") == NULL)
    return crun_make_error (err, 0, "unknown version specified");

  if (def->process && def->process->terminal && detach && context->console_socket == NULL)
    return crun_make_error (err, 0, "use --console-socket with --detach when a terminal is used");

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! detach && (options & LIBCRUN_RUN_OPTIONS_PREFORK) == 0)
    {
      ret = libcrun_copy_config_file (context->id, context->state_root, context->config_file, context->config_file_content, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = libcrun_container_run_internal (container, context, -1, err);
      force_delete_container_status (context, def);
      return ret;
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
        return crun_make_error (err, errno, "invalid read from sync pipe");

      if (status < 0)
        {
          int errno_;
          char buf[512];
          ret = TEMP_FAILURE_RETRY (read (pipefd0, &errno_, sizeof (errno_)));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "invalid read from sync pipe");

          ret = TEMP_FAILURE_RETRY (read (pipefd0, buf, sizeof (buf) - 1));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "invalid read from sync pipe");
          buf[ret] = '\0';

          return crun_make_error (err, errno_, "%s", buf);
        }

      return status;
    }

  close_and_reset (&pipefd0);

  /* forked process.  */
  ret = detach_process ();
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "detach process");

  ret = libcrun_copy_config_file (context->id, context->state_root, context->config_file, context->config_file_content, &tmp_err);
  if (UNLIKELY (ret < 0))
    goto fail;

  ret = libcrun_container_run_internal (container, context, -1, &tmp_err);
  TEMP_FAILURE_RETRY (write (pipefd1, &ret, sizeof (ret)));
  if (UNLIKELY (ret < 0))
    goto fail;

  exit (EXIT_SUCCESS);
fail:

  force_delete_container_status (context, def);
  if (tmp_err)
    {
      TEMP_FAILURE_RETRY (write (pipefd1, &(tmp_err->status), sizeof (tmp_err->status)));
      TEMP_FAILURE_RETRY (write (pipefd1, tmp_err->msg, strlen (tmp_err->msg) + 1));
      crun_error_release (&tmp_err);
    }

  exit (EXIT_FAILURE);
}

int
libcrun_container_create (libcrun_context_t *context, libcrun_container_t *container, unsigned int options,
                          libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;
  int container_ready_pipe[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  cleanup_close int exec_fifo_fd = -1;
  context->detach = 1;

  container->context = context;

  if (def->oci_version && strstr (def->oci_version, "1.0") == NULL)
    return crun_make_error (err, 0, "unknown version specified");

  ret = check_config_file (def, context, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process && def->process->terminal && context->console_socket == NULL)
    return crun_make_error (err, 0, "use --console-socket with create when a terminal is used");

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  exec_fifo_fd = libcrun_status_create_exec_fifo (context->state_root, context->id, err);
  if (UNLIKELY (exec_fifo_fd < 0))
    return exec_fifo_fd;

  context->fifo_exec_wait_fd = exec_fifo_fd;
  exec_fifo_fd = -1;

  if ((options & LIBCRUN_RUN_OPTIONS_PREFORK) == 0)
    {
      ret = libcrun_copy_config_file (context->id, context->state_root, context->config_file, context->config_file_content, err);
      if (UNLIKELY (ret < 0))
        return ret;
      ret = libcrun_container_run_internal (container, context, -1, err);
      if (UNLIKELY (ret < 0))
        force_delete_container_status (context, def);
      return ret;
    }

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
              libcrun_error_t tmp_err = NULL;
              libcrun_container_delete (context, def, context->id, true, &tmp_err);
              crun_error_release (err);
            }
          return -exit_code;
        }
      return 1;
    }

  /* forked process.  */
  ret = detach_process ();
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "detach process");

  ret = libcrun_copy_config_file (context->id, context->state_root, context->config_file, context->config_file_content, err);
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "copy config file");

  ret = libcrun_container_run_internal (container, context, pipefd1, err);
  if (UNLIKELY (ret < 0))
    {
      force_delete_container_status (context, def);
      libcrun_error ((*err)->status, "%s", (*err)->msg);
      crun_set_output_handler (log_write_to_stderr, NULL, false);
    }

  TEMP_FAILURE_RETRY (write (pipefd1, &ret, sizeof (ret)));
  exit (ret ? EXIT_FAILURE : 0);
}

int
libcrun_container_start (libcrun_context_t *context, const char *id, libcrun_error_t *err)
{
  cleanup_container libcrun_container_t *container = NULL;
  const char *state_root = context->state_root;
  runtime_spec_schema_config_schema *def;
  libcrun_container_status_t status = {};
  cleanup_close int fd = -1;
  int ret;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! ret)
    return crun_make_error (err, 0, "container `%s` is not running", id);

  ret = read_container_config_from_state (&container, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (context->notify_socket)
    {
      ret = get_notify_fd (context, container, &fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_status_write_exec_fifo (context->state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  def = container->container_def;

  if (context->notify_socket)
    {
      if (fd >= 0)
        {
          fd_set read_set;

          while (1)
            {
              struct timeval timeout = {
                .tv_sec = 0,
                .tv_usec = 10000,
              };
              FD_ZERO (&read_set);
              FD_SET (fd, &read_set);

              ret = select (fd + 1, &read_set, NULL, NULL, &timeout);
              if (UNLIKELY (ret < 0))
                return ret;
              if (ret)
                {
                  ret = handle_notify_socket (fd, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  if (ret)
                    break;
                }
              else
                {
                  ret = libcrun_is_container_running (&status, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  if (! ret)
                    return 0;
                }
            }
        }
    }

  /* The container is considered running only after we got the notification from the
     notify_socket, if any.  */
  if (def->hooks && def->hooks->poststart_len)
    {
      cleanup_close int hooks_out_fd = -1;
      cleanup_close int hooks_err_fd = -1;

      ret = open_hooks_output (container, &hooks_out_fd, &hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = do_hooks (def, status.pid, context->id, true, status.bundle, "running", (hook **) def->hooks->poststart,
                      def->hooks->poststart_len, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        crun_error_release (err);
    }

  return 0;
}

int
libcrun_get_container_state_string (const char *id, libcrun_container_status_t *status, const char *state_root,
                                    const char **container_status, int *running, libcrun_error_t *err)
{
  int ret, has_fifo = 0;
  bool paused = false;

  ret = libcrun_is_container_running (status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  *running = ret;

  if (*running)
    {
      ret = libcrun_status_has_read_exec_fifo (state_root, id, err);
      if (UNLIKELY (ret < 0))
        return ret;
      has_fifo = ret;
    }

  if (*running && ! has_fifo)
    {
      int cgroup_mode;

      cgroup_mode = libcrun_get_cgroup_mode (err);
      if (UNLIKELY (cgroup_mode < 0))
        return cgroup_mode;

      ret = libcrun_cgroup_is_container_paused (status->cgroup_path, cgroup_mode, &paused, err);
      if (UNLIKELY (ret < 0))
        {
          /*
            The cgroup might have been cleaned up by the time we try to read it, ignore both
            ENOENT and ENODEV:
            - ENOENT: if the open(CGROUP_PATH) fails because the cgroup was deleted.
            - ENODEV: if the cgroup is deleted between the open and reading the freeze status.
          */

          errno = crun_error_get_errno (err);
          if (errno == ENOENT || errno == ENODEV)
            {
              crun_error_release (err);
              *container_status = "stopped";
              return 0;
            }

          return ret;
        }
    }

  if (! *running)
    *container_status = "stopped";
  else if (has_fifo)
    *container_status = "created";
  else if (paused)
    *container_status = "paused";
  else
    *container_status = "running";

  return 0;
}

int
libcrun_container_state (libcrun_context_t *context, const char *id, FILE *out, libcrun_error_t *err)
{
  const char *const OCI_CONFIG_VERSION = "1.0.0";
  libcrun_container_status_t status = {};
  const char *state_root = context->state_root;
  const char *container_status = NULL;
  yajl_gen gen = NULL;
  const unsigned char *buf;
  int ret = 0;
  int running;
  size_t len;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_get_container_state_string (id, &status, state_root, &container_status, &running, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  ret = 0;
  gen = yajl_gen_alloc (NULL);
  if (gen == NULL)
    return crun_make_error (err, 0, "yajl_gen_alloc failed");

  yajl_gen_config (gen, yajl_gen_beautify, 1);
  yajl_gen_config (gen, yajl_gen_validate_utf8, 1);

  yajl_gen_map_open (gen);
  yajl_gen_string (gen, YAJL_STR ("ociVersion"), strlen ("ociVersion"));
  yajl_gen_string (gen, YAJL_STR (OCI_CONFIG_VERSION), strlen (OCI_CONFIG_VERSION));

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

  yajl_gen_string (gen, YAJL_STR ("owner"), strlen ("owner"));
  yajl_gen_string (gen, YAJL_STR (status.owner), strlen (status.owner));

  {
    size_t i;
    cleanup_free char *config_file = NULL;
    cleanup_container libcrun_container_t *container = NULL;
    cleanup_free char *dir = NULL;

    dir = libcrun_get_state_directory (state_root, id);
    if (UNLIKELY (dir == NULL))
      {
        ret = crun_make_error (err, 0, "cannot get state directory");
        goto exit;
      }

    ret = append_paths (&config_file, err, dir, "config.json", NULL);
    if (UNLIKELY (ret < 0))
      return ret;

    container = libcrun_container_load_from_file (config_file, err);
    if (UNLIKELY (container == NULL))
      {
        ret = crun_make_error (err, 0, "error loading config.json");
        goto exit;
      }

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
  }

  yajl_gen_map_close (gen);

  if (yajl_gen_get_buf (gen, &buf, &len) != yajl_gen_status_ok)
    {
      ret = crun_make_error (err, 0, "error generating JSON");
      goto exit;
    }

  fprintf (out, "%s\n", buf);

exit:
  if (gen)
    yajl_gen_free (gen);
  libcrun_free_container_status (&status);
  return ret;
}

int
libcrun_container_exec (libcrun_context_t *context, const char *id, runtime_spec_schema_config_schema_process *process,
                        libcrun_error_t *err)
{
  int container_status, ret;
  pid_t pid;
  libcrun_container_status_t status = {};
  const char *state_root = context->state_root;
  cleanup_close int terminal_fd = -1;
  cleanup_close int seccomp_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_free char *config_file = NULL;
  cleanup_container libcrun_container_t *container = NULL;
  cleanup_free char *dir = NULL;
  cleanup_free const char *exec_path = NULL;
  int container_ret_status[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  cleanup_close int seccomp_receiver_fd = -1;
  cleanup_close int own_seccomp_receiver_fd = -1;
  cleanup_close int seccomp_notify_fd = -1;
  const char *seccomp_notify_plugins = NULL;
  char b;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  container_status = ret;

  dir = libcrun_get_state_directory (state_root, id);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, 0, "cannot get state directory");

  ret = append_paths (&config_file, err, dir, "config.json", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  container = libcrun_container_load_from_file (config_file, err);
  if (container == NULL)
    return crun_make_error (err, 0, "error loading config.json");

  if (container_status == 0)
    return crun_make_error (err, 0, "the container `%s` is not running.", id);

  ret = block_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = open_seccomp_output (context->id, &seccomp_fd, true, context->state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (seccomp_fd >= 0)
    {
      ret = get_seccomp_receiver_fd (container, &seccomp_receiver_fd, &own_seccomp_receiver_fd, &seccomp_notify_plugins,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* This must be done before we enter a user namespace.  */
  ret = libcrun_set_rlimits (process->rlimits, process->rlimits_len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = pipe (container_ret_status);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipefd0 = container_ret_status[0];
  pipefd1 = container_ret_status[1];

  /* If the new process block doesn't specify a SELinux label or AppArmor profile, then
     use the configuration from the original config file.  */
  if (container->container_def->process)
    {
      if (process->selinux_label == NULL && container->container_def->process->selinux_label)
        process->selinux_label = xstrdup (container->container_def->process->selinux_label);

      if (process->apparmor_profile == NULL && container->container_def->process->apparmor_profile)
        process->apparmor_profile = xstrdup (container->container_def->process->apparmor_profile);
    }

  ret = initialize_security (process, err);
  if (UNLIKELY (ret < 0))
    return ret;

  pid = libcrun_join_process (container, status.pid, &status, context->detach, process->terminal ? &terminal_fd : NULL,
                              err);
  if (UNLIKELY (pid < 0))
    return pid;

  /* Process to exec.  */
  if (pid == 0)
    {
      size_t i;
      uid_t container_uid = process->user ? process->user->uid : 0;
      gid_t container_gid = process->user ? process->user->gid : 0;
      const char *cwd;
      runtime_spec_schema_config_schema_process_capabilities *capabilities = NULL;
      char **seccomp_flags = NULL;
      size_t seccomp_flags_len = 0;
      pid_t own_pid = 0;

      TEMP_FAILURE_RETRY (close (pipefd0));
      pipefd0 = -1;

      TEMP_FAILURE_RETRY (read (pipefd1, &own_pid, sizeof (own_pid)));

      cwd = process->cwd ? process->cwd : "/";
      if (chdir (cwd) < 0)
        libcrun_fail_with_error (errno, "chdir");

      ret = unblock_signals (err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = clearenv ();
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "clearenv");

      if (process->env_len)
        {
          for (i = 0; i < process->env_len; i++)
            if (putenv (process->env[i]) < 0)
              libcrun_fail_with_error (errno, "putenv `%s`", process->env[i]);
        }
      else if (container->container_def->process->env_len)
        {
          char *e;

          for (i = 0; i < container->container_def->process->env_len; i++)
            {
              e = container->container_def->process->env[i];
              if (putenv (e) < 0)
                libcrun_fail_with_error (errno, "putenv `%s`", e);
            }
        }

      if (getenv ("HOME") == NULL)
        {
          ret = set_home_env (container->container_uid);
          if (UNLIKELY (ret < 0 && errno != ENOTSUP))
            {
              setenv ("HOME", "/", 1);
              libcrun_warning ("cannot detect HOME environment variable, setting default");
            }
        }

      if (UNLIKELY (libcrun_set_selinux_exec_label (process, err) < 0))
        libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

      if (UNLIKELY (libcrun_set_apparmor_profile (process, err) < 0))
        libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

      if (container->container_def->linux && container->container_def->linux->seccomp)
        {
          seccomp_flags = container->container_def->linux->seccomp->flags;
          seccomp_flags_len = container->container_def->linux->seccomp->flags_len;
        }

      exec_path = find_executable (process->args[0], process->cwd);
      if (UNLIKELY (exec_path == NULL))
        {
          if (errno == ENOENT)
            crun_make_error (err, errno, "executable file `%s` not found in $PATH", process->args[0]);
          else
            crun_make_error (err, errno, "open executable");

          libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
        }

      if (context->kontain)
        {
          char *new_execpath;
          int rc = libcrun_kontain_nonkmexec_allowed (exec_path, &new_execpath);
          if (rc != 0)
            {
              libcrun_fail_with_error (rc, "allow non-km executable check failed");
            }
          if (new_execpath == NULL)
            {
              // Run as a payload
              rc = libcrun_kontain_argv (&process->args, &exec_path);
              if (rc != 0)
                {
                  libcrun_fail_with_error (rc, "failed to setup %s to run in a kontain VM", exec_path);
                }
            }
          else
            {
              // Run the returned path without km.
              char *pacify_maint_mk = (char *) exec_path;
              free (pacify_maint_mk);
              exec_path = new_execpath;
            }
        }

      if (container->container_def->linux && container->container_def->linux->personality)
        {
          ret = libcrun_set_personality (container->container_def->linux->personality, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = mark_for_close_fds_ge_than (context->preserve_fds + 3, err);
      if (UNLIKELY (ret < 0))
        libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

      if (! process->no_new_privileges)
        {
          cleanup_free char *seccomp_fd_payload = NULL;
          size_t seccomp_fd_payload_len = 0;

          if (seccomp_receiver_fd >= 0)
            {
              ret = get_seccomp_receiver_fd_payload (container, "running", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }

          ret = libcrun_apply_seccomp (seccomp_fd, seccomp_receiver_fd, seccomp_fd_payload,
                                       seccomp_fd_payload_len, seccomp_flags, seccomp_flags_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close_and_reset (&seccomp_fd);
          close_and_reset (&seccomp_receiver_fd);
        }

      ret = libcrun_container_setgroups (container, process, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (process->capabilities)
        capabilities = process->capabilities;
      else if (container->container_def->process)
        capabilities = container->container_def->process->capabilities;

      if (capabilities)
        {
          ret = libcrun_set_caps (capabilities, container_uid, container_gid, process->no_new_privileges, err);
          if (UNLIKELY (ret < 0))
            libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
        }

      if (process->no_new_privileges)
        {
          cleanup_free char *seccomp_fd_payload = NULL;
          size_t seccomp_fd_payload_len = 0;

          if (seccomp_receiver_fd >= 0)
            {
              ret = get_seccomp_receiver_fd_payload (container, "running", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
          ret = libcrun_apply_seccomp (seccomp_fd, seccomp_receiver_fd, seccomp_fd_payload,
                                       seccomp_fd_payload_len, seccomp_flags, seccomp_flags_len, err);
          if (UNLIKELY (ret < 0))
            return ret;

          close_and_reset (&seccomp_fd);
          close_and_reset (&seccomp_receiver_fd);
        }

      if (process->user)
        umask (process->user->umask_present ? process->user->umask : 0022);

      TEMP_FAILURE_RETRY (write (pipefd1, "0", 1));
      TEMP_FAILURE_RETRY (close (pipefd1));
      pipefd1 = -1;

      execv (exec_path, process->args);
      libcrun_fail_with_error (errno, "exec");
      _exit (EXIT_FAILURE);
    }

  TEMP_FAILURE_RETRY (close (pipefd1));
  pipefd1 = -1;

  TEMP_FAILURE_RETRY (write (pipefd0, &pid, sizeof (pid)));

  if (seccomp_fd >= 0)
    close_and_reset (&seccomp_fd);

  if (terminal_fd >= 0)
    {
      unsigned short rows = 0, cols = 0;

      if (process->console_size)
        {
          cols = process->console_size->width;
          rows = process->console_size->height;
        }

      ret = libcrun_terminal_setup_size (terminal_fd, rows, cols, err);
      if (UNLIKELY (ret < 0))
        return ret;

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
          ret = libcrun_setup_terminal_ptmx (terminal_fd, &orig_terminal, err);
          if (UNLIKELY (ret < 0))
            {
              flush_fd_to_err (context, terminal_fd);
              return ret;
            }
        }
    }

  ret = TEMP_FAILURE_RETRY (read (pipefd0, &b, sizeof (b)));
  TEMP_FAILURE_RETRY (close (pipefd0));
  pipefd0 = -1;
  if (ret != 1 || b != '0')
    ret = -1;
  else
    {
      /* Let's receive the seccomp notify fd and handle it as part of wait_for_process().  */
      if (own_seccomp_receiver_fd >= 0)
        {
          seccomp_notify_fd = receive_fd_from_socket (own_seccomp_receiver_fd, err);
          if (UNLIKELY (seccomp_notify_fd < 0))
            return seccomp_notify_fd;

          ret = close_and_reset (&own_seccomp_receiver_fd);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      ret = wait_for_process (pid, context, terminal_fd, -1, -1, seccomp_notify_fd, seccomp_notify_plugins, err);
    }

  flush_fd_to_err (context, terminal_fd);
  return ret;
}

int
libcrun_container_exec_process_file (libcrun_context_t *context, const char *id, const char *path, libcrun_error_t *err)
{
  int ret;
  size_t len;
  cleanup_free char *content = NULL;
  struct parser_context ctx = { 0, stderr };
  yajl_val tree = NULL;
  parser_error parser_err = NULL;
  runtime_spec_schema_config_schema_process *process = NULL;

  ret = read_all_file (path, &content, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = parse_json_file (&tree, content, &ctx, err);
  if (UNLIKELY (ret < 0))
    return ret;

  process = make_runtime_spec_schema_config_schema_process (tree, &ctx, &parser_err);
  if (LIKELY (process != NULL))
    ret = libcrun_container_exec (context, id, process, err);
  else
    ret = crun_make_error (err, errno, "cannot parse process file");

  free (parser_err);

  if (tree)
    yajl_tree_free (tree);

  if (process)
    free_runtime_spec_schema_config_schema_process (process);

  return ret;
}

int
libcrun_container_update (libcrun_context_t *context, const char *id, const char *content, size_t len,
                          libcrun_error_t *err)
{
  int ret;
  libcrun_container_status_t status = {};
  const char *state_root = context->state_root;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return libcrun_linux_container_update (&status, content, len, err);
}

int
libcrun_container_update_from_file (libcrun_context_t *context, const char *id, const char *file, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  size_t len;
  int ret;

  ret = read_all_file (file, &content, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return libcrun_container_update (context, id, content, len, err);
}

int
libcrun_container_spec (bool root, FILE *out, libcrun_error_t *err arg_unused)
{
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  return fprintf (out, spec_file,
                  root ? spec_pts_tty_group : "\n",
                  root ? "" : spec_user,
                  cgroup_mode == CGROUP_MODE_UNIFIED ? spec_cgroupns : "");
}

int
libcrun_container_pause (libcrun_context_t *context, const char *id, libcrun_error_t *err)
{
  int ret;
  const char *state_root = context->state_root;
  libcrun_container_status_t status = {};

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret == 0)
    return crun_make_error (err, errno, "the container `%s` is not running", id);

  return libcrun_container_pause_linux (&status, err);
}

int
libcrun_container_unpause (libcrun_context_t *context, const char *id, libcrun_error_t *err)
{
  int ret;
  const char *state_root = context->state_root;
  libcrun_container_status_t status = {};

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret == 0)
    return crun_make_error (err, errno, "the container `%s` is not running", id);

  return libcrun_container_unpause_linux (&status, err);
}

int
libcrun_container_checkpoint (libcrun_context_t *context, const char *id, libcrun_checkpoint_restore_t *cr_options,
                              libcrun_error_t *err)
{
  int ret;
  const char *state_root = context->state_root;
  libcrun_container_status_t status = {};
  cleanup_container libcrun_container_t *container = NULL;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret == 0)
    return crun_make_error (err, errno, "the container `%s` is not running", id);

  ret = read_container_config_from_state (&container, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;
  ret = libcrun_container_checkpoint_linux (&status, container, cr_options, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! cr_options->leave_running)
    return container_delete_internal (context, NULL, id, true, true, err);

  return 0;
}

int
libcrun_container_restore (libcrun_context_t *context, const char *id, libcrun_checkpoint_restore_t *cr_options,
                           libcrun_error_t *err)
{
  cleanup_container libcrun_container_t *container = NULL;
  runtime_spec_schema_config_schema *def;
  cleanup_free char *cgroup_path = NULL;
  libcrun_container_status_t status = {};
  int cgroup_mode, cgroup_manager;
  cleanup_free char *scope = NULL;
  uid_t root_uid = -1;
  gid_t root_gid = -1;
  char created[35];
  int ret;

  container = libcrun_container_load_from_file ("config.json", err);
  if (container == NULL)
    return -1;

  container->context = context;
  def = container->container_def;

  if (def->oci_version && strstr (def->oci_version, "1.0") == NULL)
    return crun_make_error (err, 0, "unknown version specified");

  ret = check_config_file (def, context, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_copy_config_file (context->id, context->state_root, context->config_file, context->config_file_content, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* The CRIU restore code uses bundle and rootfs of status. */
  status.bundle = (char *) context->bundle;
  status.rootfs = def->root->path;

  ret = libcrun_container_restore_linux (&status, container, cr_options, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Now that the process has been restored, moved it into is cgroup again.
   * The whole cgroup code is copied from libcrun_container_run_internal(). */
  def = container->container_def;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  cgroup_manager = CGROUP_MANAGER_CGROUPFS;
  if (context->systemd_cgroup)
    cgroup_manager = CGROUP_MANAGER_SYSTEMD;
  else if (context->force_no_cgroup)
    cgroup_manager = CGROUP_MANAGER_DISABLED;

  /* If we are root (either on the host or in a namespace),
   * then chown the cgroup to root in the container user namespace. */
  get_root_in_the_userns (def, container->host_uid, container->host_gid, &root_uid, &root_gid);

  {
    struct libcrun_cgroup_args cg = {
      .resources = def->linux ? def->linux->resources : NULL,
      .annotations = def->annotations,
      .cgroup_mode = cgroup_mode,
      .scope = &scope,
      .path = &cgroup_path,
      .cgroup_path = def->linux ? def->linux->cgroups_path : "",
      .manager = cgroup_manager,
      .pid = status.pid,
      .root_uid = root_uid,
      .root_gid = root_gid,
      .id = context->id,
      .systemd_subgroup = find_systemd_subgroup (container, cgroup_mode),
      .delegate_cgroup = find_delegate_cgroup (container),
    };

    ret = libcrun_cgroup_enter (&cg, err);
    if (UNLIKELY (ret < 0))
      return ret;
  }

  get_current_timestamp (created);
  context->detach = cr_options->detach;
  ret = write_container_status (container, context, status.pid, cgroup_path, scope, created, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (context->pid_file)
    {
      char buf[12];
      size_t buf_len = sprintf (buf, "%d", status.pid);
      ret = write_file_with_flags (context->pid_file, O_CREAT | O_TRUNC, buf, buf_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (! cr_options->detach)
    {
      int wait_status;
      ret = waitpid (status.pid, &wait_status, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "waitpid failed for container '%s' with %d", id, ret);

      if (WEXITSTATUS (wait_status))
        return WEXITSTATUS (wait_status);
    }

  return 0;
}
