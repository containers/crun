/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include "cgroup.h"
#include "ebpf.h"
#include "utils.h"
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/vfs.h>
#include <inttypes.h>
#include <time.h>

#ifdef HAVE_SYSTEMD
#  include <systemd/sd-bus.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libgen.h>

static const cgroups_subsystem_t cgroups_subsystems[]
    = { "cpuset",  "cpu",         "devices",    "pids",    "memory", "net_cls,net_prio", "freezer", "blkio",
        "hugetlb", "cpu,cpuacct", "perf_event", "unified", NULL };

const cgroups_subsystem_t *
libcrun_get_cgroups_subsystems (libcrun_error_t *err arg_unused)
{
  return cgroups_subsystems;
}

struct symlink_s
{
  const char *name;
  const char *target;
};

static struct symlink_s cgroup_symlinks[] = { { "cpu", "cpu,cpuacct" },
                                              { "cpuacct", "cpu,cpuacct" },
                                              { "net_cls", "net_cls,net_prio" },
                                              { "net_prio", "net_cls,net_prio" },
                                              { NULL, NULL } };

#define SYSTEMD_PROPERTY_PREFIX "org.systemd.property."

#ifndef CGROUP2_SUPER_MAGIC
#  define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#ifndef TMPFS_MAGIC
#  define TMPFS_MAGIC 0x01021994
#endif

static int
detect_cgroup_mode (libcrun_error_t *err)
{
  struct statfs stat;
  int ret;

  ret = statfs (CGROUP_ROOT, &stat);
  if (ret < 0)
    return crun_make_error (err, errno, "statfs '" CGROUP_ROOT "'");
  if (stat.f_type == CGROUP2_SUPER_MAGIC)
    return CGROUP_MODE_UNIFIED;
  if (stat.f_type != TMPFS_MAGIC)
    return crun_make_error (err, 0, "invalid file system type on '" CGROUP_ROOT "'");
  ret = statfs (CGROUP_ROOT "/unified", &stat);
  if (ret < 0 && errno != ENOENT)
    return crun_make_error (err, errno, "statfs '" CGROUP_ROOT "/unified'");
  if (ret < 0)
    return CGROUP_MODE_LEGACY;
  return stat.f_type == CGROUP2_SUPER_MAGIC ? CGROUP_MODE_HYBRID : CGROUP_MODE_LEGACY;
}

int
libcrun_get_cgroup_mode (libcrun_error_t *err)
{
  int tmp;
  static int cgroup_mode = 0;

  if (cgroup_mode)
    return cgroup_mode;

  tmp = detect_cgroup_mode (err);
  if (UNLIKELY (tmp < 0))
    return tmp;

  cgroup_mode = tmp;

  return cgroup_mode;
}

static int
is_rwm (const char *str, libcrun_error_t *err)
{
  const char *it;
  bool r = false;
  bool w = false;
  bool m = false;

  for (it = str; *it; it++)
    switch (*it)
      {
      case 'r':
        r = true;
        break;

      case 'w':
        w = true;
        break;

      case 'm':
        m = true;
        break;

      default:
        return crun_make_error (err, 0, "invalid mode specified `%s`", str);
      }

  return r && w && m ? 1 : 0;
}

enum
{
  CGROUP_MEMORY = 1 << 0,
  CGROUP_CPU = 1 << 1,
  CGROUP_HUGETLB = 1 << 2,
  CGROUP_CPUSET = 1 << 3,
  CGROUP_PIDS = 1 << 4,
  CGROUP_IO = 1 << 5,
};

static int
read_available_controllers (const char *path, libcrun_error_t *err)
{
  cleanup_close int fd;
  char *saveptr = NULL;
  const char *token;
  char *controllers;
  int available = 0;
  char buf[256];
  ssize_t ret;

  xasprintf (&controllers, "%s/cgroup.controllers", path);

  fd = TEMP_FAILURE_RETRY (open (controllers, O_RDONLY | O_CLOEXEC));
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "error opening file `%s`", path);

  ret = TEMP_FAILURE_RETRY (read (fd, buf, sizeof (buf) - 1));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error reading from file `%s`", path);
  buf[ret] = '\0';

  for (token = strtok_r (buf, " \n", &saveptr); token; token = strtok_r (NULL, " \n", &saveptr))
    {
      if (strcmp (token, "memory") == 0)
        available |= CGROUP_MEMORY;
      else if (strcmp (token, "cpu") == 0)
        available |= CGROUP_CPU;
      else if (strcmp (token, "cpuset") == 0)
        available |= CGROUP_CPUSET;
      else if (strcmp (token, "hugetlb") == 0)
        available |= CGROUP_HUGETLB;
      else if (strcmp (token, "pids") == 0)
        available |= CGROUP_PIDS;
      else if (strcmp (token, "io") == 0)
        available |= CGROUP_IO;
    }
  return available;
}

static int
write_controller_file (const char *path, int controllers_to_enable, libcrun_error_t *err)
{
  cleanup_free char *subtree_control = NULL;
  cleanup_free char *controllers = NULL;
  size_t controllers_len = 0;
  int ret;

  controllers_len = xasprintf (
      &controllers, "%s %s %s %s %s %s",
      (controllers_to_enable & CGROUP_CPU) ? "+cpu" : "",
      (controllers_to_enable & CGROUP_IO) ? "+io" : "",
      (controllers_to_enable & CGROUP_MEMORY) ? "+memory" : "",
      (controllers_to_enable & CGROUP_PIDS) ? "+pids" : "",
      (controllers_to_enable & CGROUP_CPUSET) ? "+cpuset" : "",
      (controllers_to_enable & CGROUP_HUGETLB) ? "+hugetlb" : "");

  xasprintf (&subtree_control, "%s/cgroup.subtree_control", path);
  ret = write_file (subtree_control, controllers, controllers_len, err);
  if (UNLIKELY (ret < 0))
    {
      char *saveptr = NULL;
      const char *token;
      int e;

      e = crun_error_get_errno (err);
      if (e != EPERM && e != EACCES && e != EBUSY && e != ENOENT)
        return ret;

      /* ENOENT can mean both that the file doesn't exist or the controller is not present.  */
      if (e == ENOENT)
        {
          libcrun_error_t tmp_err = NULL;
          int exists;

          exists = crun_path_exists (subtree_control, &tmp_err);
          if (UNLIKELY (exists < 0))
            {
              crun_error_release (&tmp_err);
              return ret;
            }
          /* If the file doesn't exist, then return the original ENOENT.  */
          if (exists == 0)
            return ret;
        }

      crun_error_release (err);

      /* Fallback to write each one individually.  */
      for (token = strtok_r (controllers, " ", &saveptr); token; token = strtok_r (NULL, " ", &saveptr))
        {
          ret = write_file (subtree_control, token, strlen (token), err);
          if (ret < 0)
            crun_error_release (err);
        }

      /* Refresh what controllers are available.  */
      return read_available_controllers (path, err);
    }

  /* All controllers were enabled successfully.  */
  return controllers_to_enable;
}

static int
enable_controllers (const char *path, libcrun_error_t *err)
{
  cleanup_free char *tmp_path = NULL;
  char *it;
  int ret, controllers_to_enable;

  xasprintf (&tmp_path, "%s/", path);

  ret = read_available_controllers (CGROUP_ROOT, err);
  if (UNLIKELY (ret < 0))
    return ret;

  controllers_to_enable = ret;

  /* Enable all possible controllers in the root cgroup.  */
  ret = write_controller_file (CGROUP_ROOT, controllers_to_enable, err);
  if (UNLIKELY (ret < 0))
    return ret;

  for (it = strchr (tmp_path + 1, '/'); it;)
    {
      cleanup_free char *cgroup_path = NULL;
      char *next_slash = strchr (it + 1, '/');

      *it = '\0';

      ret = append_paths (&cgroup_path, err, CGROUP_ROOT, tmp_path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = mkdir (cgroup_path, 0755);
      if (UNLIKELY (ret < 0 && errno != EEXIST))
        return crun_make_error (err, errno, "create `%s`", cgroup_path);

      if (next_slash)
        {
          ret = write_controller_file (cgroup_path, controllers_to_enable, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      *it = '/';
      it = next_slash;
    }
  return 0;
}

static int
initialize_cpuset_subsystem_rec (char *path, size_t path_len, char *cpus, char *mems, libcrun_error_t *err)
{
  cleanup_close int dirfd = -1;
  cleanup_close int mems_fd = -1;
  cleanup_close int cpus_fd = -1;
  int b_len;

  dirfd = open (path, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open `%s`", path);

  if (cpus[0] == '\0')
    {
      cpus_fd = openat (dirfd, "cpuset.cpus", O_RDWR);
      if (UNLIKELY (cpus_fd < 0))
        return crun_make_error (err, errno, "open '%s/%s'", path, "cpuset.cpus");

      b_len = TEMP_FAILURE_RETRY (read (cpus_fd, cpus, 256));
      if (UNLIKELY (b_len < 0))
        return crun_make_error (err, errno, "read from 'cpuset.cpus'");
      cpus[b_len] = '\0';
      if (cpus[0] == '\n')
        cpus[0] = '\0';
    }

  if (mems[0] == '\0')
    {
      mems_fd = openat (dirfd, "cpuset.mems", O_RDWR);
      if (UNLIKELY (mems_fd < 0))
        return crun_make_error (err, errno, "open '%s/%s'", path, "cpuset.mems");

      b_len = TEMP_FAILURE_RETRY (read (mems_fd, mems, 256));
      if (UNLIKELY (b_len < 0))
        return crun_make_error (err, errno, "read from 'cpuset.mems'");
      mems[b_len] = '\0';
      if (mems[0] == '\n')
        mems[0] = '\0';
    }

  /* look up in the parent directory.  */
  if (cpus[0] == '\0' || mems[0] == '\0')
    {
      size_t parent_path_len;
      int ret;

      for (parent_path_len = path_len - 1; parent_path_len > 1 && path[parent_path_len] != '/'; parent_path_len--)
        ;
      if (parent_path_len == 1)
        return 0;

      path[parent_path_len] = '\0';
      ret = initialize_cpuset_subsystem_rec (path, parent_path_len, cpus, mems, err);
      path[parent_path_len] = '/';
      if (UNLIKELY (ret < 0))
        {
          /* Ignore errors here and try to write the configuration we want later on.  */
          crun_error_release (err);
        }
    }

  if (cpus_fd >= 0)
    {
      b_len = TEMP_FAILURE_RETRY (write (cpus_fd, cpus, strlen (cpus)));
      if (UNLIKELY (b_len < 0))
        return crun_make_error (err, errno, "write 'cpuset.cpus'");
    }

  if (mems_fd >= 0)
    {
      b_len = TEMP_FAILURE_RETRY (write (mems_fd, mems, strlen (mems)));
      if (UNLIKELY (b_len < 0))
        return crun_make_error (err, errno, "write 'cpuset.mems'");
    }

  return 0;
}

static int
check_cgroup_v2_controller_available_wrapper (int ret, int cgroup_dirfd, const char *name, libcrun_error_t *err)
{
  if (ret == 0 || err == NULL)
    return 0;

  errno = crun_error_get_errno (err);

  /* If the file is not found, try to give a more meaningful error message.  */
  if (errno == ENOENT || errno == EPERM || errno == EACCES)
    {
      cleanup_free char *controllers = NULL;
      libcrun_error_t tmp_err = NULL;
      cleanup_free char *key = NULL;
      char *saveptr = NULL;
      bool found = false;
      const char *token;
      char *it;

      /* Check if the specified controller is enabled.  */
      key = xstrdup (name);

      it = strchr (key, '.');
      if (it == NULL)
        {
          crun_error_release (err);
          return crun_make_error (err, 0, "the specified key has not the form CONTROLLER.VALUE `%s`",
                                  name);
        }
      *it = '\0';

      /* cgroup. files are not part of a controller.  Return the original error.  */
      if (strcmp (key, "cgroup") == 0)
        return ret;

      /* If the cgroup.controllers file cannot be read, return the original error.  */
      if (read_all_file_at (cgroup_dirfd, "cgroup.controllers", &controllers, NULL, &tmp_err) < 0)
        {
          crun_error_release (&tmp_err);
          return ret;
        }
      for (token = strtok_r (controllers, " \n", &saveptr); token; token = strtok_r (NULL, " \n", &saveptr))
        {
          if (strcmp (token, key) == 0)
            {
              found = true;
              break;
            }
        }
      if (! found)
        {
          crun_error_release (err);
          return crun_make_error (err, 0, "the requested cgroup controller `%s` is not available", key);
        }
    }
  return ret;
}

static int
write_file_and_check_controllers_at (bool cgroup2, int dirfd, const char *name, const void *data, size_t len, libcrun_error_t *err)
{
  int ret;

  ret = write_file_at (dirfd, name, data, len, err);
  if (cgroup2)
    return check_cgroup_v2_controller_available_wrapper (ret, dirfd, name, err);
  return ret;
}

static int
initialize_cpuset_subsystem (const char *path, libcrun_error_t *err)
{
  cleanup_free char *tmp_path = xstrdup (path);
  char cpus_buf[257];
  char mems_buf[257];

  cpus_buf[0] = mems_buf[0] = '\0';
  return initialize_cpuset_subsystem_rec (tmp_path, strlen (tmp_path), cpus_buf, mems_buf, err);
}

static int
initialize_memory_subsystem (const char *path, libcrun_error_t *err)
{
  const char *const files[]
      = { "memory.limit_in_bytes", "memory.kmem.limit_in_bytes", "memory.memsw.limit_in_bytes", NULL };
  cleanup_close int dirfd = -1;
  int i;

  dirfd = open (path, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open `%s`", path);

  for (i = 0; files[i]; i++)
    {
      int ret;

      ret = write_file_at (dirfd, files[i], "-1", 2, err);
      if (UNLIKELY (ret < 0))
        {
          /* Ignore any error here.  */
          crun_error_release (err);
        }
    }

  return 0;
}

static int
move_process_to_cgroup (pid_t pid, const char *subsystem, const char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path_procs = NULL;
  char pid_str[16];
  int ret;

  ret = append_paths (&cgroup_path_procs, err, CGROUP_ROOT, subsystem ? subsystem : "", path ? path : "", "cgroup.procs", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  sprintf (pid_str, "%d", pid);

  return write_file (cgroup_path_procs, pid_str, strlen (pid_str), err);
}

static int
enter_cgroup_subsystem (pid_t pid, const char *subsystem, const char *path, bool create_if_missing,
                        libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  int ret;

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, subsystem ? subsystem : "", path ? path : "", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  if (create_if_missing)
    {
      ret = crun_ensure_directory (cgroup_path, 0755, false, err);
      if (UNLIKELY (ret < 0))
        {
          if (errno != EROFS)
            return crun_make_error (err, errno, "creating cgroup directory `%s`", cgroup_path);

          crun_error_release (err);
          return 0;
        }

      if (strcmp (subsystem, "cpuset") == 0)
        {
          ret = initialize_cpuset_subsystem (cgroup_path, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      if (strcmp (subsystem, "memory") == 0)
        {
          ret = initialize_memory_subsystem (cgroup_path, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  else
    {
      ret = crun_path_exists (cgroup_path, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret == 0)
        return 0;
    }

  return move_process_to_cgroup (pid, subsystem, path, err);
}

static int
is_rootless (libcrun_error_t *err)
{
  if (geteuid ())
    return 1;

  return check_running_in_user_namespace (err);
}

static int
get_file_owner (const char *path, uid_t *uid, gid_t *gid)
{
  struct stat st;
  int ret;

#ifdef HAVE_STATX
  struct statx stx;

  ret = statx (AT_FDCWD, path, AT_STATX_DONT_SYNC, STATX_UID | STATX_GID, &stx);
  if (UNLIKELY (ret < 0))
    {
      if (errno == ENOSYS || errno == EINVAL)
        goto fallback;

      return ret;
    }
  *uid = stx.stx_uid;
  *gid = stx.stx_gid;
  return ret;

fallback:
#endif
  ret = stat (path, &st);
  if (UNLIKELY (ret < 0))
    return ret;

  *uid = st.st_uid;
  *gid = st.st_gid;
  return ret;
}
static int
chown_cgroups (const char *path, uid_t uid, gid_t gid, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  cleanup_free char *delegate = NULL;
  cleanup_close int dfd = -1;
  size_t delegate_size;
  char *saveptr = NULL;
  char *name;
  int ret;

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  dfd = open (cgroup_path, O_PATH);

  ret = read_all_file ("/sys/kernel/cgroup/delegate", &delegate, &delegate_size, err);
  if (UNLIKELY (ret < 0))
    {
      if (crun_error_get_errno (err) == ENOENT)
        {
          crun_error_release (err);
          return 0;
        }
      return ret;
    }

  for (name = strtok_r (delegate, "\n", &saveptr); name; name = strtok_r (NULL, "\n", &saveptr))
    {
      ret = fchownat (dfd, name, uid, gid, AT_SYMLINK_NOFOLLOW);
      if (UNLIKELY (ret < 0))
        {
          if (errno == ENOENT)
            continue;

          return crun_make_error (err, errno, "cannot chown `%s/%s`", cgroup_path, name);
        }
    }

  return 0;
}

static int
copy_owner (const char *from, const char *to, libcrun_error_t *err)
{
  uid_t uid = 0;
  gid_t gid = 0;
  int ret;

  ret = get_file_owner (from, &uid, &gid);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot get file owner for %s", from);

  if (uid == 0 && gid == 0)
    return 0;

  return chown_cgroups (to, uid, gid, err);
}

static int
read_unified_cgroup_pid (pid_t pid, char **path, libcrun_error_t *err)
{
  int ret;
  char cgroup_path[32];
  char *from, *to;
  cleanup_free char *content = NULL;

  sprintf (cgroup_path, "/proc/%d/cgroup", pid);

  ret = read_all_file (cgroup_path, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  from = strstr (content, "0::");
  if (UNLIKELY (from == NULL))
    return crun_make_error (err, -1, "cannot find cgroup2 for the process %d", pid);

  from += 3;
  to = strchr (from, '\n');
  to = strchr (from, '\n');
  if (UNLIKELY (to == NULL))
    return crun_make_error (err, -1, "cannot parse `%s`", cgroup_path);
  *to = '\0';

  *path = xstrdup (from);
  return 0;
}

static int
enter_cgroup_v1 (int cgroup_mode, pid_t pid, const char *path, bool create_if_missing, libcrun_error_t *err)
{
  char pid_str[16];
  int ret;
  size_t i;
  int entered_any = 0;
  int rootless;
  const cgroups_subsystem_t *subsystems;

  sprintf (pid_str, "%d", pid);

  subsystems = libcrun_get_cgroups_subsystems (err);
  if (UNLIKELY (subsystems == NULL))
    return -1;

  rootless = is_rootless (err);
  if (UNLIKELY (rootless < 0))
    return rootless;

  for (i = 0; subsystems[i]; i++)
    {
      char subsystem_path[64];

      if (cgroup_mode == CGROUP_MODE_LEGACY && strcmp (subsystems[i], "unified") == 0)
        continue;

      sprintf (subsystem_path, CGROUP_ROOT "/%s", subsystems[i]);
      ret = crun_path_exists (subsystem_path, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret == 0)
        continue;

      entered_any = 1;
      ret = enter_cgroup_subsystem (pid, subsystems[i], path, create_if_missing, err);
      if (UNLIKELY (ret < 0))
        {
          int errcode = crun_error_get_errno (err);
          if (rootless && (errcode == EACCES || errcode == EPERM))
            {
              crun_error_release (err);
              continue;
            }
          return ret;
        }
    }

  return entered_any ? 0 : -1;
}

static int
enter_cgroup_v2 (pid_t pid, pid_t init_pid, const char *path, bool create_if_missing, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path_procs = NULL;
  cleanup_free char *cgroup_path = NULL;
  char pid_str[16];
  int repeat;
  int ret;

  sprintf (pid_str, "%d", pid);

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  if (create_if_missing)
    {
      ret = crun_ensure_directory (cgroup_path, 0755, false, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = append_paths (&cgroup_path_procs, err, cgroup_path, "cgroup.procs", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = write_file (cgroup_path_procs, pid_str, strlen (pid_str), err);
  if (LIKELY (ret >= 0))
    return ret;

  /* If the cgroup is not being created, try to handle EBUSY.  */
  if (create_if_missing || crun_error_get_errno (err) != EBUSY)
    return ret;

  crun_error_release (err);

  /* There are subdirectories so it is not possible to join the initial
     cgroup.  Create a subdirectory and use that.
     It can still fail if the container creates a subdirectory under
     /sys/fs/cgroup/../crun-exec/  */
  for (repeat = 0;; repeat++)
    {
      cleanup_free char *cgroup_crun_exec_path = NULL;
      cleanup_free char *cgroup_sub_path_procs = NULL;

      /* There is an init pid, try to join its cgroup.  */
      if (init_pid > 0)
        {
          ret = read_unified_cgroup_pid (init_pid, &cgroup_crun_exec_path, err);
          if (UNLIKELY (ret < 0))
            return ret;

          /* Make sure the cgroup is below the initial cgroup specified for the container.  */
          if (strncmp (path, cgroup_crun_exec_path, strlen (path)))
            {
              free (cgroup_crun_exec_path);
              cgroup_crun_exec_path = NULL;
            }
        }

      /* There is no init_pid to lookup, try a static path.  */
      if (cgroup_crun_exec_path == NULL)
        xasprintf (&cgroup_crun_exec_path, "%s/crun-exec", path);

      ret = append_paths (&cgroup_sub_path_procs, err, CGROUP_ROOT, cgroup_crun_exec_path, "cgroup.procs", NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_file (cgroup_sub_path_procs, pid_str, strlen (pid_str), err);
      if (UNLIKELY (ret < 0))
        {
          /* The init process might have moved to a different cgroup, try again.  */
          if (crun_error_get_errno (err) == EBUSY && init_pid && repeat < 20)
            {
              crun_error_release (err);
              continue;
            }
          return ret;
        }
      return copy_owner (cgroup_path_procs, cgroup_crun_exec_path, err);
    }
  return ret;
}

static int
enter_cgroup (int cgroup_mode, pid_t pid, pid_t init_pid, const char *path, bool create_if_missing,
              libcrun_error_t *err)
{
  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    return enter_cgroup_v2 (pid, init_pid, path, create_if_missing, err);

  return enter_cgroup_v1 (cgroup_mode, pid, path, create_if_missing, err);
}

int
libcrun_cgroups_create_symlinks (int dirfd, libcrun_error_t *err)
{
  int i;

  for (i = 0; cgroup_symlinks[i].name; i++)
    {
      int ret;

      ret = symlinkat (cgroup_symlinks[i].target, dirfd, cgroup_symlinks[i].name);
      if (UNLIKELY (ret < 0))
        {
          if (errno == ENOENT || errno == EEXIST)
            continue;
          return crun_make_error (err, errno, "symlinkat %s", cgroup_symlinks[i].name);
        }
    }
  return 0;
}

int
libcrun_move_process_to_cgroup (pid_t pid, pid_t init_pid, char *path, libcrun_error_t *err)
{
  int cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  if (path == NULL || *path == '\0')
    return 0;

  return enter_cgroup (cgroup_mode, pid, init_pid, path, false, err);
}

#ifdef HAVE_SYSTEMD

static void
get_systemd_scope_and_slice (const char *id, const char *cgroup_path, char **scope, char **slice)
{
  char *n;

  if (cgroup_path == NULL || cgroup_path[0] == '\0')
    {
      xasprintf (scope, "crun-%s.scope", id);
      return;
    }

  n = strchr (cgroup_path, ':');
  if (n == NULL)
    xasprintf (scope, "%s.scope", cgroup_path);
  else
    {
      xasprintf (scope, "%s.scope", n + 1);
      n = strchr (*scope, ':');
      if (n)
        *n = '-';
    }
  if (slice)
    {
      *slice = xstrdup (cgroup_path);
      n = strchr (*slice, ':');
      if (n)
        *n = '\0';
    }
}

static int
systemd_finalize (struct libcrun_cgroup_args *args, const char *suffix, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  int cgroup_mode = args->cgroup_mode;
  char **path = args->path;
  pid_t pid = args->pid;
  int ret;
  char *from, *to;
  char *saveptr = NULL;
  cleanup_free char *cgroup_path = NULL;

  xasprintf (&cgroup_path, "/proc/%d/cgroup", pid);
  ret = read_all_file (cgroup_path, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (cgroup_mode == CGROUP_MODE_LEGACY)
    {
      from = strstr (content, ":memory");
      if (UNLIKELY (from == NULL))
        return crun_make_error (err, -1, "cannot find memory controller for the current process");

      from += 8;
      to = strchr (from, '\n');
      if (UNLIKELY (to == NULL))
        return crun_make_error (err, -1, "cannot parse /proc/self/cgroup");
      *to = '\0';
      if (suffix == NULL)
        *path = xstrdup (from);
      else
        {
          ret = append_paths (path, err, from, suffix, NULL);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      *to = '\n';
    }
  else
    {
      from = strstr (content, "0::");
      if (UNLIKELY (from == NULL))
        return crun_make_error (err, -1, "cannot find cgroup2 for the current process");

      from += 3;
      to = strchr (from, '\n');
      if (UNLIKELY (to == NULL))
        return crun_make_error (err, -1, "cannot parse /proc/self/cgroup");
      *to = '\0';
      if (suffix == NULL)
        *path = xstrdup (from);
      else
        {
          ret = append_paths (path, err, from, suffix, NULL);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      *to = '\n';
    }

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      bool must_chown = false;

      if (suffix)
        {
          cleanup_free char *dir = NULL;

          ret = append_paths (&dir, err, CGROUP_ROOT, *path, NULL);
          if (UNLIKELY (ret < 0))
            return ret;

          /* On cgroup v2, processes can be only in leaf nodes.  If a suffix is used,
             move the process immediately to the new location before enabling
             the controllers.
          */
          ret = crun_ensure_directory (dir, 0755, true, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = move_process_to_cgroup (pid, NULL, *path, err);
          if (UNLIKELY (ret < 0))
            return ret;

          must_chown = true;
        }

      ret = enable_controllers (*path, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (must_chown)
        {
          ret = chown_cgroups (*path, args->root_uid, args->root_gid, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  if (cgroup_mode != CGROUP_MODE_UNIFIED && geteuid ())
    return 0;

  for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
    {
      char *subpath, *subsystem;
      subsystem = strchr (from, ':') + 1;
      subpath = strchr (subsystem, ':') + 1;
      *(subpath - 1) = '\0';

      /* on cgroup v2, ignore any subsystem except unified,
         since other subsystems are not supported anyway.  */
      if (cgroup_mode == CGROUP_MODE_UNIFIED && subsystem[0] != '\0')
        continue;

      if (strcmp (subpath, *path))
        {
          ret = enter_cgroup_subsystem (pid, subsystem, *path, true, err);
          if (UNLIKELY (ret < 0))
            {
              /* If it is a named hierarchy, skip the error.  */
              /* skip named hierarchies that have no cgroup controller */
              if (strchr (subsystem, '='))
                {
                  crun_error_release (err);
                  continue;
                }
              return ret;
            }
        }
    }

  return 0;
}

struct systemd_job_removed_s
{
  const char *path;
  const char *op;
  int terminated;
  libcrun_error_t err;
};

static int
systemd_job_removed (sd_bus_message *m, void *userdata, sd_bus_error *error arg_unused)
{
  const char *path, *unit, *result;
  uint32_t id;
  int ret;
  struct systemd_job_removed_s *d = userdata;

  ret = sd_bus_message_read (m, "uoss", &id, &path, &unit, &result);
  if (ret < 0)
    return -1;

  if (strcmp (d->path, path) == 0)
    {
      d->terminated = 1;
      if (strcmp (result, "done") != 0)
        crun_make_error (&d->err, 0, "error %s systemd unit `%s`: got `%s`", d->op, unit, result);
    }
  return 0;
}

static int
systemd_check_job_status_setup (sd_bus *bus, struct systemd_job_removed_s *data, libcrun_error_t *err)
{
  int ret;

  ret = sd_bus_match_signal_async (bus, NULL, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                   "org.freedesktop.systemd1.Manager", "JobRemoved", systemd_job_removed, NULL, data);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, -ret, "sd-bus match signal");

  return 0;
}

static int
systemd_check_job_status (sd_bus *bus, struct systemd_job_removed_s *data, const char *path, const char *op,
                          libcrun_error_t *err)
{
  int sd_err;

  data->path = path;
  data->op = op;
  while (! data->terminated)
    {
      sd_err = sd_bus_process (bus, NULL);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus process");

      if (sd_err != 0)
        continue;

      sd_err = sd_bus_wait (bus, (uint64_t) -1);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus wait");
    }

  if (data->err != NULL)
    {
      *err = data->err;
      return -1;
    }

  return 0;
}

/* Parse a gvariant string.  Support only a subset of types, just enough for systemd .  */
static int
append_systemd_annotation (sd_bus_message *m, const char *name, size_t name_len, const char *value,
                           libcrun_error_t *err)
{
  cleanup_free char *tmp_name = NULL;
  uint32_t factor = 1;
  const char *it;
  int sd_err;

  while (*value == ' ')
    value++;

  it = value;

  /* If the name has the form NameSec, convert it to NameUSec.  */
  if (name_len > 4 && name[name_len - 4] != 'U' && name[name_len - 3] == 'S' && name[name_len - 2] == 'e'
      && name[name_len - 1] == 'c')
    {
      factor = 1000000;

      tmp_name = xmalloc (name_len + 2);
      memcpy (tmp_name, name, name_len - 3);
      memcpy (tmp_name + name_len - 3, "USec", 5);

      name = tmp_name;
    }

  if ((strcmp (it, "true") == 0) || (strcmp (it, "false") == 0))
    {
      bool b = *it == 't';

      sd_err = sd_bus_message_append (m, "(sv)", name, "b", b);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (*it == '\'')
    {
      cleanup_free char *v_start = NULL;
      char *end;

      it = v_start = xstrdup (value);

      end = strchr (it + 1, '\'');
      if (end == NULL)
        return crun_make_error (err, 0, "invalid variant `%s`", value);
      *end = '\0';

      sd_err = sd_bus_message_append (m, "(sv)", name, "s", it + 1);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (has_prefix (it, "uint64 "))
    {
      char *endptr = NULL;
      uint64_t v;

      errno = 0;
      v = strtoull (it + sizeof ("uint64"), &endptr, 10);
      if (UNLIKELY (errno != 0 || *endptr))
        return crun_make_error (err, errno, "invalid value for `%s`", name);

      sd_err = sd_bus_message_append (m, "(sv)", name, "t", (uint64_t) (v * factor));
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (has_prefix (it, "int64 "))
    {
      char *endptr = NULL;
      int64_t v;

      errno = 0;
      v = strtoll (it + sizeof ("int64"), &endptr, 10);
      if (UNLIKELY (errno != 0 || *endptr))
        return crun_make_error (err, errno, "invalid value for `%s`", name);

      sd_err = sd_bus_message_append (m, "(sv)", name, "x", (int64_t) (v * factor));
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (has_prefix (it, "uint32 "))
    {
      char *endptr = NULL;
      uint32_t v;

      errno = 0;
      v = strtoul (it + sizeof ("uint32"), &endptr, 10);
      if (UNLIKELY (errno != 0 || *endptr))
        return crun_make_error (err, errno, "invalid value for `%s`", name);

      sd_err = sd_bus_message_append (m, "(sv)", name, "u", (uint32_t) (v * factor));
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }
  else if (has_prefix (it, "int32 ") || strchr (it, ' ') == NULL)
    {
      char *endptr = NULL;
      int32_t v;

      /* If no type is specified, try to parse it as int32.  */

      errno = 0;
      if (has_prefix (it, "int32 "))
        v = strtol (it + sizeof ("int32"), &endptr, 10);
      else
        v = strtol (it, &endptr, 10);
      if (UNLIKELY (errno != 0 || *endptr))
        return crun_make_error (err, errno, "invalid value for `%s`", name);

      sd_err = sd_bus_message_append (m, "(sv)", name, "i", (int32_t) (v * factor));
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      return 0;
    }

  return crun_make_error (err, errno, "unknown type for `%s`", name);
}

static int
open_sd_bus_connection (sd_bus **bus, libcrun_error_t *err)
{
  int sd_err;

  sd_err = sd_bus_default_user (bus);
  if (sd_err < 0)
    {
      sd_err = sd_bus_default_system (bus);
      if (sd_err < 0)
        return crun_make_error (err, -sd_err, "cannot open sd-bus");
    }
  return 0;
}

static int
enter_systemd_cgroup_scope (runtime_spec_schema_config_linux_resources *resources, json_map_string_string *annotations,
                            const char *scope, const char *slice, pid_t pid, libcrun_error_t *err)
{
  sd_bus *bus = NULL;
  sd_bus_message *m = NULL;
  sd_bus_message *reply = NULL;
  int sd_err, ret = 0;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  const char *object;
  struct systemd_job_removed_s job_data = {};
  int i;
  const char *boolean_opts[10];

  i = 0;
  boolean_opts[i++] = "Delegate";
  if (resources)
    {
      if (resources->cpu)
        boolean_opts[i++] = "CPUAccounting";
      if (resources->memory)
        boolean_opts[i++] = "MemoryAccounting";
      if (resources->block_io)
        boolean_opts[i++] = "IOAccounting";
      if (resources->pids)
        boolean_opts[i++] = "TasksAccounting";
    }
  boolean_opts[i++] = NULL;

  ret = open_sd_bus_connection (&bus, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  ret = systemd_check_job_status_setup (bus, &job_data, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  sd_err = sd_bus_message_new_method_call (bus, &m, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager", "StartTransientUnit");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "set up dbus message");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "ss", scope, "fail");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append scope");
      goto exit;
    }

  sd_err = sd_bus_message_open_container (m, 'a', "(sv)");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus open container");
      goto exit;
    }

  if (slice)
    {
      sd_err = sd_bus_message_append (m, "(sv)", "Slice", "s", slice);
      if (UNLIKELY (sd_err < 0))
        {
          ret = crun_make_error (err, -sd_err, "sd-bus message append Slice");
          goto exit;
        }
    }

  if (annotations)
    {
      size_t prefix_len = sizeof (SYSTEMD_PROPERTY_PREFIX) - 1;
      size_t i;

      for (i = 0; i < annotations->len; i++)
        {
          size_t len;

          if (! has_prefix (annotations->keys[i], SYSTEMD_PROPERTY_PREFIX))
            continue;

          len = strlen (annotations->keys[i]);
          if (len < prefix_len + 3)
            {
              ret = crun_make_error (err, EINVAL, "invalid systemd property name `%s`", annotations->keys[i]);
              goto exit;
            }

          ret = append_systemd_annotation (m, annotations->keys[i] + prefix_len, len - prefix_len,
                                           annotations->values[i], err);
          if (UNLIKELY (ret < 0))
            goto exit;
        }
    }

  sd_err = sd_bus_message_append (m, "(sv)", "Description", "s", "libcrun container");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append Description");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "(sv)", "PIDs", "au", 1, pid);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append PIDs");
      goto exit;
    }

  for (i = 0; boolean_opts[i]; i++)
    {
      sd_err = sd_bus_message_append (m, "(sv)", boolean_opts[i], "b", 1);
      if (UNLIKELY (sd_err < 0))
        {
          ret = crun_make_error (err, -sd_err, "sd-bus message append %s", boolean_opts[i]);
          goto exit;
        }
    }

  sd_err = sd_bus_message_close_container (m);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus close container");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "a(sa(sv))", 0);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append");
      goto exit;
    }

  sd_err = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call");
      goto exit;
    }

  sd_err = sd_bus_message_read (reply, "o", &object);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message read");
      goto exit;
    }

  ret = systemd_check_job_status (bus, &job_data, object, "creating", err);

exit:
  if (bus)
    sd_bus_unref (bus);
  if (m)
    sd_bus_message_unref (m);
  if (reply)
    sd_bus_message_unref (reply);
  sd_bus_error_free (&error);
  return ret;
}

static int
destroy_systemd_cgroup_scope (const char *scope, libcrun_error_t *err)
{
  sd_bus *bus = NULL;
  sd_bus_message *m = NULL;
  sd_bus_message *reply = NULL;
  int ret = 0;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  const char *object;
  struct systemd_job_removed_s job_data = {};

  ret = open_sd_bus_connection (&bus, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  ret = systemd_check_job_status_setup (bus, &job_data, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  ret = sd_bus_message_new_method_call (bus, &m, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                        "org.freedesktop.systemd1.Manager", "StopUnit");
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, -ret, "set up dbus message");
      goto exit;
    }

  ret = sd_bus_message_append (m, "ss", scope, "replace");
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, -ret, "sd-bus message append");
      goto exit;
    }

  ret = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call");
      goto exit;
    }

  ret = sd_bus_message_read (reply, "o", &object);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, -ret, "sd-bus message read");
      goto exit;
    }

  ret = systemd_check_job_status (bus, &job_data, object, "removing", err);

exit:
  if (bus)
    sd_bus_unref (bus);
  if (m)
    sd_bus_message_unref (m);
  if (reply)
    sd_bus_message_unref (reply);
  sd_bus_error_free (&error);
  return ret;
}

#endif

static int
libcrun_cgroup_enter_no_manager (struct libcrun_cgroup_args *args, libcrun_error_t *err arg_unused)
{
  *args->path = NULL;
  return 0;
}

static int
libcrun_cgroup_enter_cgroupfs (struct libcrun_cgroup_args *args, libcrun_error_t *err)
{
  int cgroup_mode = args->cgroup_mode;
  char **path = args->path;
  const char *cgroup_path = args->cgroup_path;
  pid_t pid = args->pid;
  const char *id = args->id;

  if (cgroup_path == NULL)
    xasprintf (path, "/%s", id);
  else
    {
      if (cgroup_path[0] == '/')
        *path = xstrdup (cgroup_path);
      else
        xasprintf (path, "/%s", cgroup_path);
    }

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      int ret;

      ret = enable_controllers (*path, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return enter_cgroup (cgroup_mode, pid, 0, *path, true, err);
}

static int
libcrun_cgroup_enter_systemd (struct libcrun_cgroup_args *args, libcrun_error_t *err)
{
#ifdef HAVE_SYSTEMD
  runtime_spec_schema_config_linux_resources *resources = args->resources;
  const char *cgroup_path = args->cgroup_path;
  cleanup_free char *slice = NULL;
  const char *id = args->id;
  pid_t pid = args->pid;
  char *scope = NULL;
  int ret;

  get_systemd_scope_and_slice (id, cgroup_path, &scope, &slice);

  *args->scope = scope;

  ret = enter_systemd_cgroup_scope (resources, args->annotations, scope, slice, pid, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return systemd_finalize (args, args->systemd_subgroup, err);
#else
  return libcrun_cgroup_enter_cgroupfs (args, err);
#endif
}

int
libcrun_cgroup_enter (struct libcrun_cgroup_args *args, libcrun_error_t *err)
{
  int cgroup_mode = args->cgroup_mode;
  char **path = args->path;
  int manager = args->manager;
  uid_t root_uid = args->root_uid;
  uid_t root_gid = args->root_gid;
  libcrun_error_t tmp_err = NULL;
  int rootless;
  int ret;

  if (cgroup_mode == CGROUP_MODE_HYBRID)
    {
      /* We don't really support hybrid mode, so check that cgroups2 is not using any controller.  */

      size_t len;
      cleanup_free char *buffer = NULL;

      ret = read_all_file (CGROUP_ROOT "/unified/cgroup.controllers", &buffer, &len, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (len > 0)
        return crun_make_error (err, 0, "cgroups in hybrid mode not supported, drop all controllers from cgroupv2");
    }

  switch (manager)
    {
    case CGROUP_MANAGER_DISABLED:
      ret = libcrun_cgroup_enter_no_manager (args, err);
      break;

    case CGROUP_MANAGER_SYSTEMD:
      ret = libcrun_cgroup_enter_systemd (args, err);
      break;

    case CGROUP_MANAGER_CGROUPFS:
      ret = libcrun_cgroup_enter_cgroupfs (args, err);
      break;

    default:
      return crun_make_error (err, EINVAL, "unknown cgroup manager specified %d", manager);
    }
  if (LIKELY (ret >= 0))
    {
      if (cgroup_mode == CGROUP_MODE_UNIFIED && (root_uid != (uid_t) -1 || root_gid != (gid_t) -1))
        return chown_cgroups (*path, root_uid, root_gid, err);

      if (args->resources)
        return libcrun_update_cgroup_resources (args->cgroup_mode, args->resources, *path, err);

      return 0;
    }

  rootless = is_rootless (&tmp_err);
  if (UNLIKELY (rootless < 0))
    {
      crun_error_release (err);
      *err = tmp_err;
      return rootless;
    }

  if (rootless > 0 && (cgroup_mode != CGROUP_MODE_UNIFIED || manager != CGROUP_MANAGER_SYSTEMD))
    {
      /* Ignore cgroups errors and set there is no cgroup path to use.  */
      free (*path);
      *path = NULL;
      crun_error_release (err);
      return 0;
    }

  return ret;
}

int
libcrun_cgroup_is_container_paused (const char *cgroup_path, int cgroup_mode, bool *paused, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  cleanup_free char *path = NULL;
  const char *state;
  int ret;

  if (cgroup_path == NULL || cgroup_path[0] == '\0')
    return 0;

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      state = "1";

      ret = append_paths (&path, err, CGROUP_ROOT, cgroup_path, "cgroup.freeze", NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      state = "FROZEN";

      ret = append_paths (&path, err, CGROUP_ROOT "/freezer", cgroup_path, "freezer.state", NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = read_all_file (path, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  *paused = strstr (content, state) != NULL;
  return 0;
}

static int
libcrun_cgroup_pause_unpause_with_mode (const char *cgroup_path, int cgroup_mode, const bool pause,
                                        libcrun_error_t *err)
{
  cleanup_free char *path = NULL;
  const char *state = "";
  int ret;

  if (cgroup_path == NULL || cgroup_path[0] == '\0')
    return crun_make_error (err, 0, "cannot %s the container without a cgroup", pause ? "pause" : "resume");

  if (cgroup_mode == CGROUP_MODE_UNIFIED)
    {
      state = pause ? "1" : "0";
      ret = append_paths (&path, err, CGROUP_ROOT, cgroup_path, "cgroup.freeze", NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      state = pause ? "FROZEN" : "THAWED";
      ret = append_paths (&path, err, CGROUP_ROOT "/freezer", cgroup_path, "freezer.state", NULL);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = write_file (path, state, strlen (state), err);
  if (ret >= 0)
    return 0;
  return ret;
}

int
libcrun_cgroup_pause_unpause (const char *cgroup_path, const bool pause, libcrun_error_t *err)
{
  int cgroup_mode;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (cgroup_mode < 0)
    return cgroup_mode;

  return libcrun_cgroup_pause_unpause_with_mode (cgroup_path, cgroup_mode, pause, err);
}

static int
read_pids_cgroup (int dfd, bool recurse, pid_t **pids, size_t *n_pids, size_t *allocated, libcrun_error_t *err)
{
  cleanup_close int clean_dfd = dfd;
  cleanup_close int tasksfd = -1;
  cleanup_free char *buffer = NULL;
  char *saveptr = NULL;
  size_t n_new_pids;
  size_t len;
  char *it;
  int ret;

  tasksfd = openat (dfd, "cgroup.procs", O_RDONLY | O_CLOEXEC);
  if (tasksfd < 0)
    return crun_make_error (err, errno, "open cgroup.procs");

  ret = read_all_fd (tasksfd, "cgroup.procs", &buffer, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  for (n_new_pids = 0, it = buffer; it; it = strchr (it + 1, '\n'))
    n_new_pids++;

  if (*allocated < *n_pids + n_new_pids + 1)
    {
      *allocated = *n_pids + n_new_pids + 1;
      *pids = xrealloc (*pids, sizeof (pid_t) * *allocated);
    }

  for (it = strtok_r (buffer, "\n", &saveptr); it; it = strtok_r (NULL, "\n", &saveptr))
    {
      pid_t pid = strtoul (it, NULL, 10);

      if (pid > 0)
        (*pids)[(*n_pids)++] = pid;
    }
  (*pids)[*n_pids] = 0;

  if (recurse)
    {
      cleanup_dir DIR *dir = NULL;
      struct dirent *de;

      dir = fdopendir (dfd);
      if (UNLIKELY (dir == NULL))
        return crun_make_error (err, errno, "open cgroup sub-directory");
      /* Now dir owns the dfd descriptor.  */
      clean_dfd = -1;

      for (de = readdir (dir); de; de = readdir (dir))
        {
          int nfd;

          if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
            continue;

          if (de->d_type != DT_DIR)
            continue;

          nfd = openat (dirfd (dir), de->d_name, O_DIRECTORY | O_CLOEXEC);
          if (UNLIKELY (nfd < 0))
            return crun_make_error (err, errno, "open cgroup directory %s", de->d_name);
          ret = read_pids_cgroup (nfd, recurse, pids, n_pids, allocated, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  return 0;
}

int
libcrun_cgroup_read_pids (const char *path, bool recurse, pid_t **pids, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  size_t n_pids, allocated;
  int dirfd;
  int mode;
  int ret;

  if (path == NULL || *path == '\0')
    return 0;

  mode = libcrun_get_cgroup_mode (err);
  if (mode < 0)
    return mode;

  switch (mode)
    {
    case CGROUP_MODE_UNIFIED:
      ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
      break;

    case CGROUP_MODE_HYBRID:
    case CGROUP_MODE_LEGACY:
      ret = append_paths (&cgroup_path, err, CGROUP_ROOT "/memory", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
      break;

    default:
      return crun_make_error (err, 0, "invalid cgroup mode %d", mode);
    }

  dirfd = open (cgroup_path, O_DIRECTORY | O_CLOEXEC);
  if (dirfd < 0)
    return crun_make_error (err, errno, "open %s", cgroup_path);

  n_pids = 0;
  allocated = 0;

  return read_pids_cgroup (dirfd, recurse, pids, &n_pids, &allocated, err);
}

int
libcrun_cgroup_killall_signal (const char *path, int signal, libcrun_error_t *err)
{
  int ret;
  size_t i;
  cleanup_free pid_t *pids = NULL;

  if (path == NULL || *path == '\0')
    return 0;

  ret = libcrun_cgroup_pause_unpause (path, true, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  ret = libcrun_cgroup_read_pids (path, true, &pids, err);
  if (UNLIKELY (ret < 0))
    {
      if (crun_error_get_errno (err) != ENOENT)
        return ret;

      /* If the file doesn't exist then the container was already killed.  */
      crun_error_release (err);
    }

  for (i = 0; pids && pids[i]; i++)
    {
      ret = kill (pids[i], signal);
      if (UNLIKELY (ret < 0 && errno != ESRCH))
        return crun_make_error (err, errno, "kill process %d", pids[i]);
    }

  ret = libcrun_cgroup_pause_unpause (path, false, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  return 0;
}

static int
rmdir_all_fd (int dfd)
{
  cleanup_dir DIR *dir = NULL;
  struct dirent *next;

  dir = fdopendir (dfd);
  if (dir == NULL)
    return -1;

  dfd = dirfd (dir);

  for (next = readdir (dir); next; next = readdir (dir))
    {
      const char *name = next->d_name;
      int ret;

      if (name[0] == '.' && name[1] == '\0')
        continue;
      if (name[0] == '.' && name[1] == '.' && name[2] == '\0')
        continue;

      if (next->d_type != DT_DIR)
        continue;

      ret = unlinkat (dfd, name, AT_REMOVEDIR);
      if (ret < 0 && errno == EBUSY)
        {
          cleanup_close int child_dfd = openat (dfd, name, O_DIRECTORY | O_CLOEXEC);
          if (child_dfd < 0)
            return child_dfd;

          return rmdir_all_fd (child_dfd);
        }
    }
  return 0;
}

static int
rmdir_all (const char *path)
{
  int ret;
  cleanup_close int dfd = open (path, O_DIRECTORY | O_CLOEXEC);
  if (UNLIKELY (dfd < 0))
    return dfd;

  ret = rmdir_all_fd (dfd);
  if (UNLIKELY (ret < 0))
    return ret;

  return rmdir (path);
}

int
libcrun_cgroup_killall (const char *path, libcrun_error_t *err)
{
  return libcrun_cgroup_killall_signal (path, SIGKILL, err);
}

int
libcrun_cgroup_destroy (const char *id, const char *path, const char *scope, int manager, libcrun_error_t *err)
{
  int ret;
  size_t i;
  int mode;
  const cgroups_subsystem_t *subsystems;
  bool repeat = true;

  (void) id;
  (void) manager;
  (void) scope;

  if (path == NULL || *path == '\0')
    return 0;

  subsystems = libcrun_get_cgroups_subsystems (err);
  if (UNLIKELY (subsystems == NULL))
    return -1;

  mode = libcrun_get_cgroup_mode (err);
  if (mode < 0)
    return mode;

  ret = libcrun_cgroup_killall (path, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

#ifdef HAVE_SYSTEMD
  if (manager == CGROUP_MANAGER_SYSTEMD)
    {
      ret = destroy_systemd_cgroup_scope (scope, err);
      if (UNLIKELY (ret < 0))
        crun_error_release (err);
    }
#endif

  do
    {
      repeat = false;

      if (mode == CGROUP_MODE_UNIFIED)
        {
          cleanup_free char *cgroup_path = NULL;

          ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
          if (UNLIKELY (ret < 0))
            return ret;
          ret = rmdir (cgroup_path);
          if (ret < 0 && errno == EBUSY)
            {
              ret = rmdir_all (cgroup_path);
              if (ret < 0)
                repeat = true;
            }
        }
      else
        {
          for (i = 0; subsystems[i]; i++)
            {
              cleanup_free char *cgroup_path = NULL;

              if (mode == CGROUP_MODE_LEGACY && strcmp (subsystems[i], "unified") == 0)
                continue;

              ret = append_paths (&cgroup_path, err, CGROUP_ROOT, subsystems[i], path, NULL);
              if (UNLIKELY (ret < 0))
                return ret;

              ret = rmdir (cgroup_path);
              if (ret < 0 && errno == EBUSY)
                {
                  ret = rmdir_all (cgroup_path);
                  if (ret < 0)
                    repeat = true;
                }
            }
        }

      if (repeat)
        {
          struct timespec req = {
            .tv_sec = 0,
            .tv_nsec = 100000,
          };

          nanosleep (&req, NULL);

          ret = libcrun_cgroup_killall (path, err);
          if (UNLIKELY (ret < 0))
            crun_error_release (err);
        }
    }
  while (repeat);

  return 0;
}

/* The parser generates different structs but they are really all the same.  */
typedef runtime_spec_schema_defs_linux_block_io_device_throttle throttling_s;

static int
write_blkio_v1_resources_throttling (int dirfd, const char *name, throttling_s **throttling, size_t throttling_len,
                                     libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;
  cleanup_close int fd = -1;

  if (throttling == NULL)
    return 0;

  fd = openat (dirfd, name, O_WRONLY);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open %s", name);

  for (i = 0; i < throttling_len; i++)
    {
      int ret;
      size_t len;
      len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %" PRIu64 "\n", throttling[i]->major, throttling[i]->minor,
                     throttling[i]->rate);

      ret = TEMP_FAILURE_RETRY (write (fd, fmt_buf, len));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write %s", name);
    }
  return 0;
}

static int
write_blkio_v2_resources_throttling (int fd, const char *name, throttling_s **throttling, size_t throttling_len,
                                     libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;

  if (throttling == NULL)
    return 0;

  for (i = 0; i < throttling_len; i++)
    {
      int ret;
      size_t len;
      len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %s=%" PRIu64 "\n", throttling[i]->major, throttling[i]->minor, name,
                     throttling[i]->rate);

      ret = TEMP_FAILURE_RETRY (write (fd, fmt_buf, len));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write %s", name);
    }
  return 0;
}

static int
write_blkio_resources (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_block_io *blkio,
                       libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;
  /* convert linearly from 10-1000 to 1-10000.  */
#define CONVERT_WEIGHT_TO_CGROUPS_V2(x) (1 + ((x) -10) * 9999 / 990)

  if (blkio->weight)
    {
      uint32_t val = blkio->weight;

      if (cgroup2)
        val = CONVERT_WEIGHT_TO_CGROUPS_V2 (val);

      len = sprintf (fmt_buf, "%" PRIu32, val);
      ret = write_file_at (dirfd, cgroup2 ? "io.bfq.weight" : "blkio.weight", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->leaf_weight)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set leaf_weight with cgroupv2");
      len = sprintf (fmt_buf, "%d", blkio->leaf_weight);
      ret = write_file_at (dirfd, "blkio.leaf_weight", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->weight_device_len)
    {
      if (cgroup2)
        {
          cleanup_close int wfd = -1;
          size_t i;

          wfd = openat (dirfd, "io.bfq.weight", O_WRONLY);
          if (UNLIKELY (wfd < 0))
            return crun_make_error (err, errno, "open io.weight");
          for (i = 0; i < blkio->weight_device_len; i++)
            {
              uint32_t w = CONVERT_WEIGHT_TO_CGROUPS_V2 (blkio->weight_device[i]->weight);

              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %i\n", blkio->weight_device[i]->major,
                             blkio->weight_device[i]->minor, w);
              ret = TEMP_FAILURE_RETRY (write (wfd, fmt_buf, len));
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write io.weight");

              /* Ignore blkio->weight_device[i]->leaf_weight.  */
            }
        }
      else
        {
          cleanup_close int w_device_fd = -1;
          cleanup_close int w_leafdevice_fd = -1;
          size_t i;

          w_device_fd = openat (dirfd, "blkio.weight_device", O_WRONLY);
          if (UNLIKELY (w_device_fd < 0))
            return crun_make_error (err, errno, "open blkio.weight_device");

          w_leafdevice_fd = openat (dirfd, "blkio.leaf_weight_device", O_WRONLY);
          if (UNLIKELY (w_leafdevice_fd < 0))
            return crun_make_error (err, errno, "open blkio.leaf_weight_device");

          for (i = 0; i < blkio->weight_device_len; i++)
            {
              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64" %" PRIu16 "\n", blkio->weight_device[i]->major, blkio->weight_device[i]->minor,
                             blkio->weight_device[i]->weight);
              ret = TEMP_FAILURE_RETRY (write (w_device_fd, fmt_buf, len));
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write blkio.weight_device");

              len = sprintf (fmt_buf, "%" PRIu64 ":%" PRIu64 " %" PRIu16 "\n", blkio->weight_device[i]->major, blkio->weight_device[i]->minor,
                             blkio->weight_device[i]->leaf_weight);
              ret = TEMP_FAILURE_RETRY (write (w_leafdevice_fd, fmt_buf, len));
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, errno, "write blkio.leaf_weight_device");
            }
        }
    }
  if (cgroup2)
    {
      cleanup_close int wfd = -1;
      const char *name = "io.max";

      wfd = openat (dirfd, name, O_WRONLY);
      if (UNLIKELY (wfd < 0))
        {
          ret = crun_make_error (err, errno, "open `%s`", name);
          return check_cgroup_v2_controller_available_wrapper (ret, dirfd, name, err);
        }

      ret = write_blkio_v2_resources_throttling (wfd, "rbps", (throttling_s **) blkio->throttle_read_bps_device,
                                                 blkio->throttle_read_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "wbps", (throttling_s **) blkio->throttle_write_bps_device,
                                                 blkio->throttle_write_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "riops", (throttling_s **) blkio->throttle_read_iops_device,
                                                 blkio->throttle_read_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v2_resources_throttling (wfd, "wiops", (throttling_s **) blkio->throttle_write_iops_device,
                                                 blkio->throttle_write_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.read_bps_device",
                                                 (throttling_s **) blkio->throttle_read_bps_device,
                                                 blkio->throttle_read_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.write_bps_device",
                                                 (throttling_s **) blkio->throttle_write_bps_device,
                                                 blkio->throttle_write_bps_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.read_iops_device",
                                                 (throttling_s **) blkio->throttle_read_iops_device,
                                                 blkio->throttle_read_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_blkio_v1_resources_throttling (dirfd, "blkio.throttle.write_iops_device",
                                                 (throttling_s **) blkio->throttle_write_iops_device,
                                                 blkio->throttle_write_iops_device_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_network_resources (int dirfd_netclass, int dirfd_netprio, runtime_spec_schema_config_linux_resources_network *net,
                         libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;
  if (net->class_id)
    {
      len = sprintf (fmt_buf, "%d", net->class_id);
      ret = write_file_at (dirfd_netclass, "net_cls.classid", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (net->priorities_len)
    {
      size_t i;
      cleanup_close int fd = -1;
      fd = openat (dirfd_netprio, "net_prio.ifpriomap", O_WRONLY);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open `net_prio.ifpriomap`");

      for (i = 0; i < net->priorities_len; i++)
        {
          len = sprintf (fmt_buf, "%s %d\n", net->priorities[i]->name, net->priorities[i]->priority);
          ret = TEMP_FAILURE_RETRY (write (fd, fmt_buf, len));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write net_prio.ifpriomap");
        }
    }

  return 0;
}

static int
write_hugetlb_resources (int dirfd, bool cgroup2,
                         runtime_spec_schema_config_linux_resources_hugepage_limits_element **htlb, size_t htlb_len,
                         libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;
  for (i = 0; i < htlb_len; i++)
    {
      cleanup_free char *filename = NULL;
      const char *suffix;
      size_t len;
      int ret;

      suffix = cgroup2 ? "max" : "limit_in_bytes";

      xasprintf (&filename, "hugetlb.%s.%s", htlb[i]->page_size, suffix);

      len = sprintf (fmt_buf, "%" PRIu64, htlb[i]->limit);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd, filename, fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_devices_resources_v1 (int dirfd, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                            libcrun_error_t *err)
{
  size_t i, len;
  int ret;
  char *default_devices[]
      = { "c *:* m",   "b *:* m",   "c 1:3 rwm",   "c 1:8 rwm", "c 1:7 rwm",    "c 5:0 rwm", "c 1:5 rwm",
          "c 1:9 rwm", "c 5:1 rwm", "c 136:* rwm", "c 5:2 rwm", "c 10:200 rwm", NULL };

  for (i = 0; i < devs_len; i++)
    {
      /* It is plenty of room for "TYPE MAJOR:MINOR ACCESS", where type is one char, and ACCESS is at most 3.   */
#define FMT_BUF_LEN 64
      char fmt_buf[FMT_BUF_LEN];
      const char *file = devs[i]->allow ? "devices.allow" : "devices.deny";

      if (devs[i]->type == NULL || devs[i]->type[0] == 'a')
        {
          strcpy (fmt_buf, "a");
          len = 1;
        }
      else
        {
          char fmt_buf_major[16];
          char fmt_buf_minor[16];

#define FMT_DEV(x, b)               \
  do                                \
    {                               \
      if (x##_present)              \
        sprintf (b, "%" PRIi64, x); \
      else                          \
        strcpy (b, "*");            \
    }                               \
  while (0)

          FMT_DEV (devs[i]->major, fmt_buf_major);
          FMT_DEV (devs[i]->minor, fmt_buf_minor);

          len = snprintf (fmt_buf, FMT_BUF_LEN - 1, "%s %s:%s %s", devs[i]->type, fmt_buf_major, fmt_buf_minor,
                          devs[i]->access);
          /* Make sure it is still a NUL terminated string.  */
          fmt_buf[len] = '\0';
        }
      ret = write_file_at (dirfd, file, fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (i = 0; default_devices[i]; i++)
    {
      ret = write_file_at (dirfd, "devices.allow", default_devices[i], strlen (default_devices[i]), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_devices_resources_v2_internal (int dirfd, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                                     libcrun_error_t *err)
{
  int i, ret;
  cleanup_free struct bpf_program *program = NULL;
  struct default_dev_s
  {
    char type;
    int major;
    int minor;
    const char *access;
  };
  struct default_dev_s default_devices[] = {
    { 'c', -1, -1, "m" }, { 'b', -1, -1, "m" },    { 'c', 1, 3, "rwm" }, { 'c', 1, 8, "rwm" },
    { 'c', 1, 7, "rwm" }, { 'c', 5, 0, "rwm" },    { 'c', 1, 5, "rwm" }, { 'c', 1, 9, "rwm" },
    { 'c', 5, 1, "rwm" }, { 'c', 136, -1, "rwm" }, { 'c', 5, 2, "rwm" }, { 'c', 10, 200, "rwm" },
  };

  program = bpf_program_new (2048);

  program = bpf_program_init_dev (program, err);
  if (UNLIKELY (program == NULL))
    return -1;

  for (i = (sizeof (default_devices) / sizeof (default_devices[0])) - 1; i >= 0; i--)
    {
      program = bpf_program_append_dev (program, default_devices[i].access, default_devices[i].type,
                                        default_devices[i].major, default_devices[i].minor, true, err);
      if (UNLIKELY (program == NULL))
        return -1;
    }
  for (i = devs_len - 1; i >= 0; i--)
    {
      char type = 'a';
      int minor = -1, major = -1;
      if (devs[i]->type != NULL)
        type = devs[i]->type[0];

      if (devs[i]->major_present)
        major = devs[i]->major;
      if (devs[i]->minor_present)
        minor = devs[i]->minor;

      program = bpf_program_append_dev (program, devs[i]->access, type, major, minor, devs[i]->allow, err);
      if (UNLIKELY (program == NULL))
        return -1;
    }

  program = bpf_program_complete_dev (program, err);
  if (UNLIKELY (program == NULL))
    return -1;

  ret = libcrun_ebpf_load (program, dirfd, NULL, err);
  if (ret < 0)
    return ret;

  return 0;
}

static int
write_devices_resources_v2 (int dirfd, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                            libcrun_error_t *err)
{
  int ret;
  size_t i;
  bool can_skip = true;

  ret = write_devices_resources_v2_internal (dirfd, devs, devs_len, err);
  if (LIKELY (ret == 0))
    return 0;

  /* If writing the resources ebpf failed, check if it is fine to ignore the error.  */
  for (i = 0; i < devs_len; i++)
    {
      if (devs[i]->allow_present && ! devs[i]->allow)
        {
          can_skip = false;
          break;
        }
    }

  if (! can_skip)
    {
      libcrun_error_t tmp_err = NULL;
      int rootless;

      rootless = is_rootless (&tmp_err);
      if (UNLIKELY (rootless < 0))
        {
          crun_error_release (err);
          *err = tmp_err;
          return ret;
        }
      if (rootless)
        can_skip = true;
    }

  if (can_skip)
    {
      crun_error_release (err);
      ret = 0;
    }

  return ret;
}

static int
write_devices_resources (int dirfd, bool cgroup2, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                         libcrun_error_t *err)
{
  if (cgroup2)
    return write_devices_resources_v2 (dirfd, devs, devs_len, err);

  return write_devices_resources_v1 (dirfd, devs, devs_len, err);
}

/* use for cgroupv2 files with .min, .max, .low, or .high suffix */
static int
cg_itoa (char *buf, int64_t value, bool cgroup2)
{
  if (! (cgroup2 && value == -1))
    return sprintf (buf, "%" PRIi64, value);

  memcpy (buf, "max", 4);
  return 3;
}

static int
write_memory (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_memory *memory, libcrun_error_t *err)
{
  char limit_buf[32];
  size_t limit_buf_len;

  if (! memory->limit_present)
    return 0;

  limit_buf_len = cg_itoa (limit_buf, memory->limit, cgroup2);

  return write_file_at (dirfd, cgroup2 ? "memory.max" : "memory.limit_in_bytes", limit_buf, limit_buf_len, err);
}

static int
write_memory_swap (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_memory *memory,
                   libcrun_error_t *err)
{
  int ret;
  int64_t swap;
  char *filename;
  char swap_buf[32];
  size_t swap_buf_len;

  if (! memory->swap_present)
    return 0;

  swap = memory->swap;
  if (cgroup2 && memory->swap != -1)
    {
      if (! memory->limit_present)
        return crun_make_error (err, 0, "cannot set swap limit without the memory limit");
      if (memory->swap < memory->limit)
        return crun_make_error (err, 0, "cannot set memory+swap limit less than the memory limit");

      swap -= memory->limit;
    }

  swap_buf_len = cg_itoa (swap_buf, swap, cgroup2);

  filename = cgroup2 ? "memory.swap.max" : "memory.memsw.limit_in_bytes";

  ret = write_file_and_check_controllers_at (cgroup2, dirfd, filename,
                                             swap_buf, swap_buf_len, err);
  if (UNLIKELY (ret < 0))
    {
      /* If the swap cgroup is not enabled, and the limit is either 0
         on cgroup v2 or same as the memory limit on cgroup v1,
         ignore the error.  */
      if (crun_error_get_errno (err) == ENOENT)
        {
          if ((cgroup2 && swap == 0)
              || (!cgroup2 && swap == memory->limit))
            {
              crun_error_release (err);
              return 0;
            }
        }
    }
  return ret;
}

static int
write_memory_resources (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_memory *memory,
                        libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[32];
  bool memory_limits_written = false;

  if (memory->limit_present)
    {
      ret = write_memory (dirfd, cgroup2, memory, err);
      if (ret >= 0)
        memory_limits_written = true;
      else
        {
          if (cgroup2 || crun_error_get_errno (err) != EINVAL)
            return ret;

          /*
            If we get an EINVAL error on cgroup v1 we reverse
            the order we write the memory limit and the swap.
            Attempt to write again the memory limit once the memory
            swap is written.
          */
          crun_error_release (err);
        }
    }

  ret = write_memory_swap (dirfd, cgroup2, memory, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (memory->limit_present && ! memory_limits_written)
    {
      ret = write_memory (dirfd, cgroup2, memory, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memory->kernel_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set kernel memory with cgroupv2");

      len = sprintf (fmt_buf, "%" PRIu64, memory->kernel);
      ret = write_file_at (dirfd, "memory.kmem.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memory->reservation_present)
    {
      len = sprintf (fmt_buf, "%" PRIu64, memory->reservation);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd, cgroup2 ? "memory.low" : "memory.soft_limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->disable_oom_killer)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot disable OOM killer with cgroupv2");

      ret = write_file_at (dirfd, "memory.oom_control", "1", 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->kernel_tcp_present)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set kernel TCP with cgroupv2");

      len = sprintf (fmt_buf, "%" PRIu64, memory->kernel_tcp);
      ret = write_file_at (dirfd, "memory.kmem.tcp.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->swappiness && memory->swappiness <= 100)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "cannot set memory swappiness with cgroupv2");

      len = sprintf (fmt_buf, "%" PRIu64, memory->swappiness);
      ret = write_file_at (dirfd, "memory.swappiness", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_pids_resources (int dirfd, bool cgroup2, runtime_spec_schema_config_linux_resources_pids *pids,
                      libcrun_error_t *err)
{
  if (pids->limit)
    {
      char fmt_buf[32];
      size_t len;
      int ret;

      len = cg_itoa (fmt_buf, pids->limit, cgroup2);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd, "pids.max", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_cpu_resources (int dirfd_cpu, bool cgroup2, runtime_spec_schema_config_linux_resources_cpu *cpu,
                     libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[64];
  int64_t period = -1;
  int64_t quota = -1;

  /* convert linearly from 2-262144 to 1-10000.  */
#define CONVERT_SHARES_TO_CGROUPS_V2(x) (1 + (((x) -2) * 9999) / 262142)

  if (cpu->shares)
    {
      uint32_t val = cpu->shares;

      if (cgroup2)
        val = CONVERT_SHARES_TO_CGROUPS_V2 (val);

      len = sprintf (fmt_buf, "%u", val);

      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpu, cgroup2 ? "cpu.weight" : "cpu.shares", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->period)
    {
      if (cgroup2)
        period = cpu->period;
      else
        {
          len = sprintf (fmt_buf, "%" PRIu64, cpu->period);
          ret = write_file_at (dirfd_cpu, "cpu.cfs_period_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  if (cpu->quota)
    {
      if (cgroup2)
        quota = cpu->quota;
      else
        {
          len = sprintf (fmt_buf, "%" PRIu64, cpu->quota);
          ret = write_file_at (dirfd_cpu, "cpu.cfs_quota_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  if (cpu->realtime_period)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "realtime period not supported on cgroupv2");
      len = sprintf (fmt_buf, "%" PRIu64, cpu->realtime_period);
      ret = write_file_at (dirfd_cpu, "cpu.rt_period_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->realtime_runtime)
    {
      if (cgroup2)
        return crun_make_error (err, 0, "realtime runtime not supported on cgroupv2");
      len = sprintf (fmt_buf, "%" PRIu64, cpu->realtime_runtime);
      ret = write_file_at (dirfd_cpu, "cpu.rt_runtime_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (cgroup2 && (quota > 0 || period > 0))
    {
      if (period < 0)
        period = 100000;
      if (quota < 0)
        len = sprintf (fmt_buf, "max %" PRIi64, period);
      else
        len = sprintf (fmt_buf, "%" PRIi64 " %" PRIi64, quota, period);
      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpu, "cpu.max", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_cpuset_resources (int dirfd_cpuset, int cgroup2, runtime_spec_schema_config_linux_resources_cpu *cpu,
                        libcrun_error_t *err)
{
  int ret;

  if (cpu->cpus)
    {
      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpuset, "cpuset.cpus", cpu->cpus, strlen (cpu->cpus), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->mems)
    {
      ret = write_file_and_check_controllers_at (cgroup2, dirfd_cpuset, "cpuset.mems", cpu->mems, strlen (cpu->mems), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
update_cgroup_v1_resources (runtime_spec_schema_config_linux_resources *resources, char *path, libcrun_error_t *err)
{
  int ret;

  if (resources->block_io)
    {
      cleanup_free char *path_to_blkio = NULL;
      cleanup_close int dirfd_blkio = -1;
      runtime_spec_schema_config_linux_resources_block_io *blkio = resources->block_io;

      ret = append_paths (&path_to_blkio, err, CGROUP_ROOT "/blkio", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_blkio = open (path_to_blkio, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_blkio < 0))
        return crun_make_error (err, errno, "open %s", path_to_blkio);

      ret = write_blkio_resources (dirfd_blkio, false, blkio, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->network)
    {
      cleanup_free char *path_to_netclass = NULL;
      cleanup_close int dirfd_netclass = -1;
      cleanup_free char *path_to_netprio = NULL;
      cleanup_close int dirfd_netprio = -1;
      runtime_spec_schema_config_linux_resources_network *network = resources->network;

      ret = append_paths (&path_to_netclass, err, CGROUP_ROOT "/net_cls", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = append_paths (&path_to_netprio, err, CGROUP_ROOT "/net_prio", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_netclass = open (path_to_netclass, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_netclass < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_netclass);

      dirfd_netprio = open (path_to_netprio, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_netprio < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_netprio);

      ret = write_network_resources (dirfd_netclass, dirfd_netprio, network, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->hugepage_limits_len)
    {
      cleanup_free char *path_to_htlb = NULL;
      cleanup_close int dirfd_htlb = -1;

      ret = append_paths (&path_to_htlb, err, CGROUP_ROOT "/hugetlb", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;
      dirfd_htlb = open (path_to_htlb, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_htlb < 0))
        return crun_make_error (err, errno, "open %s", path_to_htlb);

      ret = write_hugetlb_resources (dirfd_htlb, false, resources->hugepage_limits, resources->hugepage_limits_len,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->devices_len)
    {
      cleanup_free char *path_to_devs = NULL;
      cleanup_close int dirfd_devs = -1;

      ret = append_paths (&path_to_devs, err, CGROUP_ROOT "/devices", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_devs = open (path_to_devs, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_devs < 0))
        return crun_make_error (err, errno, "open %s", path_to_devs);

      ret = write_devices_resources (dirfd_devs, false, resources->devices, resources->devices_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->memory)
    {
      cleanup_free char *path_to_mem = NULL;
      cleanup_close int dirfd_mem = -1;

      ret = append_paths (&path_to_mem, err, CGROUP_ROOT "/memory", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_mem = open (path_to_mem, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_mem < 0))
        return crun_make_error (err, errno, "open %s", path_to_mem);

      ret = write_memory_resources (dirfd_mem, false, resources->memory, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->pids)
    {
      cleanup_free char *path_to_pid = NULL;
      cleanup_close int dirfd_pid = -1;

      ret = append_paths (&path_to_pid, err, CGROUP_ROOT "/pids", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_pid = open (path_to_pid, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_pid < 0))
        return crun_make_error (err, errno, "open %s", path_to_pid);

      ret = write_pids_resources (dirfd_pid, false, resources->pids, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->cpu)
    {
      cleanup_free char *path_to_cpu = NULL;
      cleanup_close int dirfd_cpu = -1;
      cleanup_free char *path_to_cpuset = NULL;
      cleanup_close int dirfd_cpuset = -1;

      ret = append_paths (&path_to_cpu, err, CGROUP_ROOT "/cpu", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_cpu = open (path_to_cpu, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_cpu < 0))
        return crun_make_error (err, errno, "open %s", path_to_cpu);
      ret = write_cpu_resources (dirfd_cpu, false, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (resources->cpu->cpus == NULL && resources->cpu->mems == NULL)
        return 0;

      ret = append_paths (&path_to_cpuset, err, CGROUP_ROOT "/cpuset", path, NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_cpuset = open (path_to_cpuset, O_DIRECTORY | O_RDONLY);
      if (UNLIKELY (dirfd_cpuset < 0))
        return crun_make_error (err, errno, "open %s", path_to_cpuset);

      ret = write_cpuset_resources (dirfd_cpuset, false, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->unified && resources->unified->len > 0)
    return crun_make_error (err, 0, "invalid configuration: cannot use unified on cgroup v1");

  return 0;
}

static int
write_unified_resources (int cgroup_dirfd, runtime_spec_schema_config_linux_resources *resources, libcrun_error_t *err)
{
  size_t i;
  int ret;

  for (i = 0; i < resources->unified->len; i++)
    {
      size_t len;

      if (strchr (resources->unified->keys[i], '/'))
        return crun_make_error (err, 0, "key `%s` must be a file name without any slash", resources->unified->keys[i]);

      len = strlen (resources->unified->values[i]);
      ret = write_file_and_check_controllers_at (true, cgroup_dirfd, resources->unified->keys[i], resources->unified->values[i], len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
update_cgroup_v2_resources (runtime_spec_schema_config_linux_resources *resources, char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  cleanup_close int cgroup_dirfd = -1;
  int ret;

  if (resources->network)
    return crun_make_error (err, 0, "network limits not supported on cgroupv2");

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  cgroup_dirfd = open (cgroup_path, O_DIRECTORY);
  if (UNLIKELY (cgroup_dirfd < 0))
    return crun_make_error (err, errno, "open %s", cgroup_path);

  if (resources->devices_len)
    {
      ret = write_devices_resources (cgroup_dirfd, true, resources->devices, resources->devices_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->memory)
    {
      ret = write_memory_resources (cgroup_dirfd, true, resources->memory, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->pids)
    {
      ret = write_pids_resources (cgroup_dirfd, true, resources->pids, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->cpu)
    {
      ret = write_cpu_resources (cgroup_dirfd, true, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = write_cpuset_resources (cgroup_dirfd, true, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (resources->block_io)
    {
      ret = write_blkio_resources (cgroup_dirfd, true, resources->block_io, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->hugepage_limits_len)
    {
      ret = write_hugetlb_resources (cgroup_dirfd, true, resources->hugepage_limits, resources->hugepage_limits_len,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Write unified resources if any.  They have higher precedence and override any previous setting.  */
  if (resources->unified)
    {
      ret = write_unified_resources (cgroup_dirfd, resources, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

int
libcrun_update_cgroup_resources (int cgroup_mode, runtime_spec_schema_config_linux_resources *resources, char *path,
                                 libcrun_error_t *err)
{
  if (path == NULL)
    {
      size_t i;

      if (resources->block_io || resources->network || resources->hugepage_limits_len || resources->memory
          || resources->pids || resources->cpu)
        return crun_make_error (err, 0, "cannot set limits without cgroups");

      for (i = 0; i < resources->devices_len; i++)
        {
          int rwm;

          rwm = is_rwm (resources->devices[i]->access, err);
          if (UNLIKELY (rwm < 0))
            return rwm;

          if (rwm == 0)
            return crun_make_error (err, 0, "cannot set limits without cgroups");
        }

      return 0;
    }
  switch (cgroup_mode)
    {
    case CGROUP_MODE_UNIFIED:
      return update_cgroup_v2_resources (resources, path, err);

    case CGROUP_MODE_LEGACY:
    case CGROUP_MODE_HYBRID:
      return update_cgroup_v1_resources (resources, path, err);

    default:
      return crun_make_error (err, 0, "invalid cgroup mode");
    }
}
