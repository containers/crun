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
#include "linux.h"
#include "utils.h"
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <signal.h>
#include "terminal.h"
#include "cgroup.h"
#include "status.h"
#include <sys/socket.h>

struct remount_s
{
  struct remount_s *next;
  char *target;
  unsigned long flags;
  char *data;
};

struct private_data_s
{
  struct remount_s *remounts;

  /* Filled by libcrun_set_namespaces().  Useful to query what
     namespaces are available.  */
  int unshare_flags;

  char *host_notify_socket_path;
  char *container_notify_socket_path;
  int mount_etc_from_host;
};

struct linux_namespace_s
{
  const char *name;
  int value;
};

static struct private_data_s *
get_private_data (struct libcrun_container_s *container)
{
  if (container->private_data == NULL)
    {
      struct private_data_s *p = xmalloc (sizeof (*p));
      memset (p, 0, sizeof (*p));
      container->private_data = p;
    }
  return container->private_data;
}

static struct linux_namespace_s namespaces[] =
  {
    {"mount", CLONE_NEWNS},
    {"cgroup", CLONE_NEWCGROUP},
    {"network", CLONE_NEWNET},
    {"ipc", CLONE_NEWIPC},
    {"pid", CLONE_NEWPID},
    {"uts", CLONE_NEWUTS},
    {"user", CLONE_NEWUSER},
    {NULL, 0}
  };

static int
find_namespace (const char *name)
{
  struct linux_namespace_s *it;
  for (it = namespaces; it->name; it++)
    if (strcmp (it->name, name) == 0)
      return it->value;
  return -1;
}

static int
syscall_clone (unsigned long flags, void *child_stack)
{
  return (int) syscall (__NR_clone, flags, child_stack);
}

static void
get_uid_gid_from_def (oci_container *def, uid_t *uid, gid_t *gid)
{
  *uid = 0;
  *gid = 0;

  if (def->process->user)
    {
      if (def->process->user->uid)
        *uid = def->process->user->uid;
      if (def->process->user->gid)
        *gid = def->process->user->gid;
    }
}

struct propagation_flags_s
  {
    const char *name;
    int clear;
    int flags;
  };

static struct propagation_flags_s propagation_flags[] =
  {
    {"defaults", 0, 0},
    {"rbind", 0, MS_REC | MS_BIND},
    {"ro", 0, MS_RDONLY},
    {"rw", 1, MS_RDONLY},
    {"suid", 1, MS_NOSUID},
    {"nosuid", 0, MS_NOSUID},
    {"dev", 1, MS_NODEV},
    {"nodev", 0, MS_NODEV},
    {"exec", 1, MS_NOEXEC},
    {"noexec", 0, MS_NOEXEC},
    {"sync", 0, MS_SYNCHRONOUS},
    {"async", 1, MS_SYNCHRONOUS},
    {"dirsync", 0, MS_DIRSYNC},
    {"remount", 0, MS_REMOUNT},
    {"mand", 0, MS_MANDLOCK},
    {"nomand", 1, MS_MANDLOCK},
    {"atime", 1, MS_NOATIME},
    {"noatime", 0, MS_NOATIME},
    {"diratime", 1, MS_NODIRATIME},
    {"nodiratime", 0, MS_NODIRATIME},
    {"relatime", 0, MS_RELATIME},
    {"norelatime", 1, MS_RELATIME},
    {"strictatime", 0, MS_STRICTATIME},
    {"nostrictatime", 1, MS_STRICTATIME},
    {"shared", 0, MS_SHARED},
    {"rshared", 0, MS_REC | MS_SHARED},
    {"slave", 0, MS_SLAVE},
    {"rslave", 0, MS_REC | MS_SLAVE},
    {"private", 0, MS_PRIVATE},
    {"rprivate", 0, MS_REC | MS_PRIVATE},
    {"unbindable", 0, MS_UNBINDABLE},
    {"runbindable", 0, MS_REC | MS_UNBINDABLE},
    {NULL, 0}
  };

static unsigned long
get_mount_flags (const char *name, int current_flags, int *found)
{
  struct propagation_flags_s *it;
  if (found)
    *found = 0;
  for (it = propagation_flags; it->name; it++)
    if (strcmp (it->name, name) == 0)
      {
        if (found)
          *found = 1;

        if (it->clear)
          return current_flags & ~it->flags;

        return current_flags | it->flags;
      }
  return 0;
}

static unsigned long
get_mount_flags_or_option (const char *name, int current_flags, char **option)
{
  int found;
  cleanup_free char *prev = NULL;
  unsigned long flags = get_mount_flags (name, current_flags, &found);
  if (found)
    return flags;

  prev = *option;
  if (*option && **option)
    xasprintf (option, "%s,%s", *option, name);
  else
    *option = xstrdup (name);

  return 0;
}

int
pivot_root (const char * new_root, const char * put_old)
{
  return syscall (__NR_pivot_root, new_root, put_old);
}

static void
free_remount (struct remount_s *r)
{
  free (r->data);
  free (r->target);
  free (r);
}

static struct remount_s *
make_remount (const char *target, unsigned long flags, const char *data, struct remount_s *next)
{
  struct remount_s *ret = xmalloc (sizeof (*ret));
  ret->target = xstrdup (target);
  ret->flags = flags;
  ret->data = data ? xstrdup (data) : NULL;
  ret->next = next;
  return ret;
}

static int
do_mount (libcrun_container *container,
          const char *source,
          const char *target,
          const char *fstype,
          unsigned long mountflags,
          const void *data,
          int skip_labelling,
          libcrun_error_t *err)
{
  int ret = 0;
  cleanup_free char *data_with_label = NULL;
  const char *label = container->container_def->linux->mount_label;

  if (!skip_labelling)
    {
      ret = add_selinux_mount_label (&data_with_label, data, label, err);
      if  (ret < 0)
        return ret;
      data = data_with_label;
    }

#define ALL_PROPAGATIONS (MS_REC | MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)

  if ((fstype && fstype[0]) || (mountflags & MS_BIND))
    {
      unsigned long flags = mountflags & ~MS_RDONLY;
      if ((mountflags & MS_BIND) == 0)
        flags &= ~ALL_PROPAGATIONS;
      ret = mount (source, target, fstype, flags, data);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "mount '%s' to '%s'", source, target);
    }

  if (mountflags & ALL_PROPAGATIONS)
    {
      unsigned long rec = mountflags & MS_REC;
      unsigned long propagations = mountflags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE);
      unsigned long all_propagations[] = {MS_SHARED, MS_PRIVATE, MS_SLAVE, MS_UNBINDABLE, 0};
      size_t s;
      for (s = 0; all_propagations[s]; s++)
        {
          if (!(propagations & all_propagations[s]))
            continue;
          ret = mount ("none", target, "", rec | all_propagations[s], "");
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "set propagation for '%s'", target);
        }
    }

  if (mountflags & MS_RDONLY)
    {
      unsigned long remount_flags = MS_REMOUNT | MS_BIND | MS_RDONLY;
      struct remount_s *r = make_remount (target, remount_flags, NULL, get_private_data (container)->remounts);
      get_private_data (container)->remounts = r;
    }

  return ret;
}

static int
do_mount_cgroup (libcrun_container *container,
                 const char *source,
                 const char *target,
                 const char *fstype,
                 unsigned long mountflags,
                 const void *data,
                 libcrun_error_t *err)
{
  int ret;
  size_t i;
  const char *subsystems[] = {"devices", "cpuset", "pids", "memory", "net_cls,net_prio",
                              "freezer", "blkio", "hugetlb", "cpu,cpuacct", "perf_event", NULL};
  cleanup_free char *cgroup_unified = NULL;

  xasprintf (&cgroup_unified, "%s/unified", target);

  ret = do_mount (container, source, target, "tmpfs", mountflags, "size=1024k", 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = mkdir (cgroup_unified, 0755);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "mkdir for '%s' failed", cgroup_unified);

  ret = do_mount (container, source, cgroup_unified, "cgroup2", mountflags, NULL, 1, err);
  if (UNLIKELY (ret < 0))
    return ret;

  for (i = 0; subsystems[i]; i++)
    {
      cleanup_free char *subsystem_path = NULL;
      xasprintf (&subsystem_path, "%s/%s", target, subsystems[i]);

      ret = mkdir (subsystem_path, 0755);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "mkdir for '%s' failed", cgroup_unified);

      ret = do_mount (container, source, subsystem_path, "cgroup", mountflags, subsystems[i], 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

struct device_s
{
  const char *path;
  char *type;
  int major;
  int minor;
  int mode;
};

struct device_s needed_devs[] =
  {
    {"/dev/null", "c", 1, 3, 0666},
    {"/dev/zero", "c", 1, 5, 0666},
    {"/dev/full", "c", 1, 7, 0666},
    {"/dev/tty", "c", 5, 0, 0666},
    {"/dev/random", "c", 1, 8, 0666},
    {"/dev/urandom", "c", 1, 9, 0666},
    {NULL, '\0', 0, 0, 0}
  };

static int
create_dev (libcrun_container *container, int devfd, struct device_s *device, const char *rootfs, int binds, libcrun_error_t *err)
{
  int ret;
  dev_t dev;
  mode_t type = (device->type[0] == 'b') ? S_IFBLK : ((device->type[0] == 'p') ? S_IFIFO : S_IFCHR);
  const char *fullname = device->path;
  /* Skip the common prefix /dev.  */
  const char *basename = device->path + 5;
  if (binds)
    {
      cleanup_free char *path_to_container = NULL;
      xasprintf (&path_to_container, "%s/dev/%s", rootfs, basename);

      ret = create_file_if_missing_at (devfd, basename, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = do_mount (container, fullname, path_to_container, "", MS_BIND | MS_PRIVATE, "", 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  else
    {
      dev = makedev (device->major, device->minor);
      ret = mknodat (devfd, basename, device->mode | type, dev);
      /* We don't fail when the file already exists.  */
      if (UNLIKELY (ret < 0 && errno == EEXIST))
        return 0;
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "mknod '%s'", basename);
    }
  return 0;
}

static int
create_missing_devs (libcrun_container *container, const char *rootfs, int binds, libcrun_error_t *err)
{
  int ret;
  size_t i;
  struct device_s *it;
  cleanup_close int dirfd = open (rootfs, O_DIRECTORY | O_RDONLY);
  cleanup_close int devfd = -1;
  oci_container *def = container->container_def;

  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open rootfs directory '%s'", rootfs);

  devfd = openat (dirfd, "dev", O_RDONLY | O_DIRECTORY);
  if (UNLIKELY (devfd < 0))
    return crun_make_error (err, errno, "open /dev directory in '%s'", rootfs);

  for (i = 0; i < def->linux->devices_len; i++)
    {
      struct device_s device = {def->linux->devices[i]->path,
                                     def->linux->devices[i]->type,
                                     def->linux->devices[i]->major,
                                     def->linux->devices[i]->minor,
                                     def->linux->devices[i]->file_mode};
      ret = create_dev (container, devfd, &device, rootfs, binds, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (it = needed_devs; it->path; it++)
    {
      ret = create_dev (container, devfd, it, rootfs, binds, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = symlinkat ("/proc/self/fd", devfd, "fd");
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "creating symlink for /dev/fd");

  ret = symlinkat ("/proc/self/fd/0", devfd, "stdin");
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "creating symlink for /dev/stdin");

  ret = symlinkat ("/proc/self/fd/1", devfd, "stdout");
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "creating symlink for /dev/stdout");

  ret = symlinkat ("/proc/self/fd/2", devfd, "stderr");
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "creating symlink for /dev/stderr");

  ret = symlinkat ("/proc/kcore", devfd, "core");
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "creating symlink for /dev/core");

  ret = symlinkat ("/dev/pts/ptmx", devfd, "ptmx");
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "creating symlink for /dev/ptmx");

  return 0;
}

static int
do_masked_and_readonly_paths (libcrun_container *container, const char *rootfs, libcrun_error_t *err)
{
  size_t i;
  int ret;
  oci_container *def = container->container_def;

  for (i = 0; i < def->linux->masked_paths_len; i++)
    {
      cleanup_free char *path = NULL;
      int dir;
      xasprintf (&path, "%s%s", rootfs, def->linux->masked_paths[i]);

      ret = crun_path_exists (path, 1, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (ret == 0)
        continue;

      dir = crun_dir_p (path, err);
      if (UNLIKELY (dir < 0))
        return ret;

      if (dir)
        ret = do_mount (container, "tmpfs", path, "tmpfs", MS_RDONLY, "size=0k", 0, err);
      else
        ret = do_mount (container, "/dev/null", path, "", MS_BIND | MS_UNBINDABLE | MS_PRIVATE | MS_REC, "", 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  for (i = 0; i < def->linux->readonly_paths_len; i++)
    {
      cleanup_free char *path = NULL;

      xasprintf (&path, "%s%s", rootfs, def->linux->readonly_paths[i]);

      ret = crun_path_exists (path, 1, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (ret == 0)
        continue;

      ret = do_mount (container, path, path, "", MS_BIND | MS_UNBINDABLE | MS_PRIVATE | MS_RDONLY | MS_REC, "", 0, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
do_pivot (libcrun_container *container, const char *rootfs, libcrun_error_t *err)
{
  int ret;
  cleanup_close int oldrootfd = open ("/", O_DIRECTORY | O_RDONLY);
  cleanup_close int newrootfd = open (rootfs, O_DIRECTORY | O_RDONLY);

  if (UNLIKELY (oldrootfd < 0))
    return crun_make_error (err, errno, "open '/'");
  if (UNLIKELY (newrootfd < 0))
    return crun_make_error (err, errno, "open '%s'", rootfs);

  ret = fchdir (newrootfd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fchdir '%s'", rootfs);

  ret = pivot_root (".", ".");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pivot_root");

  ret = fchdir (oldrootfd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fchdir '%s'", rootfs);

  ret = do_mount (container, "", ".", "", MS_PRIVATE | MS_REC, "", 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = umount2 (".", MNT_DETACH);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "umount oldroot");

  ret = chdir ("/");
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chdir to newroot");

  return 0;
}

static int
get_default_flags (libcrun_container *container, const char *destination, char **data)
{
  if (strcmp (destination, "/proc") == 0)
      return 0;
  if (strcmp (destination, "/dev/cgroup") == 0
      || strcmp (destination, "/sys/fs/cgroup") == 0)
    {
      *data = xstrdup ("none,name=");
      return MS_NOEXEC | MS_NOSUID | MS_STRICTATIME;
    }
  if (strcmp (destination, "/dev") == 0)
    {
      *data = xstrdup ("mode=755");
      return MS_NOEXEC | MS_STRICTATIME;
    }
  if (strcmp (destination, "/dev/shm") == 0)
    {
      *data = xstrdup ("mode=1777,size=65536k");
      return MS_NOEXEC | MS_NOSUID | MS_NODEV;
    }
  if (strcmp (destination, "/dev/mqueue") == 0)
      return MS_NOEXEC | MS_NOSUID | MS_NODEV;
  if (strcmp (destination, "/dev/pts") == 0)
    {
      if (container->host_uid == 0)
        *data = xstrdup ("newinstance,ptmxmode=0666,mode=620,gid=5");
      else
        *data = xstrdup ("newinstance,ptmxmode=0666,mode=620");
      return MS_NOEXEC | MS_NOSUID;
    }
  if (strcmp (destination, "/sys") == 0)
      return MS_NOEXEC | MS_NOSUID | MS_NODEV;

  return 0;
}

static int
finalize_mounts (libcrun_container *container, const char *rootfs, int is_user_ns, libcrun_error_t *err)
{
  int ret;
  struct remount_s *r;
  for (r = get_private_data (container)->remounts; r;)
    {
      struct remount_s *next = r->next;
      ret = mount ("none", r->target, "", r->flags, r->data);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "remount '%s'", r->target);

      free_remount (r);

      r = next;
    }
  get_private_data (container)->remounts = NULL;
  return 0;
}

static int
do_mounts (libcrun_container *container, const char *rootfs, libcrun_error_t *err)
{
  size_t i;
  int ret;
  oci_container *def = container->container_def;
  for (i = 0; i < def->mounts_len; i++)
    {
      cleanup_free char *target = NULL;
      cleanup_free char *data = NULL;
      char *type;
      char *source;
      unsigned long flags = 0;
      int skip_labelling;
      int is_dir = 1;

      if (rootfs)
        xasprintf (&target, "%s/%s", rootfs, def->mounts[i]->destination + 1);
      else
        target = xstrdup (def->mounts[i]->destination);

      if (def->mounts[i]->options == NULL)
        flags = get_default_flags (container, def->mounts[i]->destination, &data);
      else
        {
          size_t j;
          for (j = 0; j < def->mounts[i]->options_len; j++)
            {
              flags |= get_mount_flags_or_option (def->mounts[i]->options[j], flags, &data);
            }
        }

      type = def->mounts[i]->type;

      if (strcmp (type, "bind") == 0)
        {
          if (strcmp (def->mounts[i]->destination, "/dev") == 0)
            get_private_data (container)->mount_etc_from_host = 1;
          flags |= MS_BIND;
        }

      if (def->mounts[i]->source && (flags & MS_BIND))
        {
          is_dir = crun_dir_p (def->mounts[i]->source, err);
          if (UNLIKELY (is_dir < 0))
            return ret;
        }

      if (is_dir)
        {
          ret = crun_ensure_directory (target, 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          ret = crun_ensure_file (target, 0755, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      source = def->mounts[i]->source ? def->mounts[i]->source : type;

      skip_labelling = strcmp (type, "sysfs") == 0
        || strcmp (type, "proc") == 0
        || strcmp (type, "mqueue") == 0;

      if (strcmp (type, "cgroup") == 0)
        {
          ret = do_mount_cgroup (container, source, target, type, flags, data, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          ret = do_mount (container, source, target, type, flags, data, skip_labelling, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  return 0;
}

static int
do_notify_socket (libcrun_container *container, int *notify_socket_out, const char *rootfs, libcrun_error_t *err)
{
  const char *notify_socket = container->context->notify_socket;
  cleanup_free char *host_notify_socket_path = NULL;
  cleanup_free char *container_notify_socket_path = NULL;
  cleanup_free char *state_dir = libcrun_get_state_directory (container->context->state_root, container->context->id);
  cleanup_close int notify_fd = -1;
  int ret;

  *notify_socket_out = -1;
  if (notify_socket == NULL)
    return 0;

  xasprintf (&container_notify_socket_path, "%s%s", rootfs, notify_socket);
  xasprintf (&host_notify_socket_path, "%s/notify", state_dir);

  notify_fd = open_unix_domain_socket (host_notify_socket_path, 1, err);
  if (UNLIKELY (notify_fd < 0))
    return notify_fd;

  ret = chmod (host_notify_socket_path, 0777);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "chmod");

  get_private_data (container)->host_notify_socket_path = host_notify_socket_path;
  get_private_data (container)->container_notify_socket_path = container_notify_socket_path;
  host_notify_socket_path = container_notify_socket_path = NULL;
  *notify_socket_out = notify_fd;
  notify_fd = -1;
  return 0;
}

static int
do_finalize_notify_socket (libcrun_container *container, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *host_notify_socket_path = get_private_data (container)->host_notify_socket_path;
  cleanup_free char *container_notify_socket_path = get_private_data (container)->container_notify_socket_path;
  get_private_data (container)->host_notify_socket_path = get_private_data (container)->container_notify_socket_path = NULL;

  if (host_notify_socket_path == NULL || container_notify_socket_path == NULL)
    return 0;

  ret = create_file_if_missing (container_notify_socket_path, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = do_mount (container, host_notify_socket_path, container_notify_socket_path, "", MS_BIND | MS_PRIVATE, "", 0, err);
  if (UNLIKELY (ret < 0))
   return ret;

  return 0;
}

int
libcrun_set_mounts (libcrun_container *container, const char *rootfs, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret = 0, is_user_ns = 0;
  unsigned long rootfsPropagation = 0;

  if (def->linux->rootfs_propagation)
    rootfsPropagation = get_mount_flags (def->linux->rootfs_propagation, 0, NULL);
  else
    rootfsPropagation = MS_REC | MS_PRIVATE;

  ret = do_mount (container, "", "/", "", MS_REC | rootfsPropagation, "", 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = do_mount (container, def->root->path, rootfs, "", MS_BIND | MS_REC, "", 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->root->readonly)
    {
      unsigned long remount_flags = MS_REMOUNT | MS_BIND | MS_RDONLY;
      struct remount_s *r = make_remount (def->root->path, remount_flags, "", get_private_data (container)->remounts);
      get_private_data (container)->remounts = r;
    }

  ret = do_mounts (container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  is_user_ns = (get_private_data (container)->unshare_flags & CLONE_NEWUSER);
  if (!is_user_ns)
    {
      is_user_ns = check_running_in_user_namespace (err);
      if (UNLIKELY (is_user_ns < 0))
        return is_user_ns;
    }

  if (get_private_data (container)->mount_etc_from_host == 0)
    {
      ret = create_missing_devs (container, rootfs, is_user_ns, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = do_finalize_notify_socket (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = do_masked_and_readonly_paths (container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = finalize_mounts (container, rootfs, is_user_ns, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = do_pivot (container, rootfs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 0;
}

static int
uidgidmap_helper (char *helper, pid_t pid, char *map_file, libcrun_error_t *err)
{
#define MAX_ARGS 20
  char pid_fmt[16];
  char *args[MAX_ARGS + 1];
  char *next;
  size_t nargs = 0;
  args[nargs++] = helper;
  sprintf (pid_fmt, "%d", pid);
  args[nargs++] = pid_fmt;
  next = map_file;
  while (nargs < MAX_ARGS)
    {
      char *p = strsep (&next, " \n");
      if (next == NULL)
        break;
      args[nargs++] = p;
    }
  args[nargs++] = NULL;

  return run_process (args, err);
}

static int
newgidmap (pid_t pid, char *map_file, libcrun_error_t *err)
{
  return uidgidmap_helper ("/usr/bin/newgidmap", pid, map_file, err);
}

static int
newuidmap (pid_t pid, char *map_file, libcrun_error_t *err)
{
  return uidgidmap_helper ("/usr/bin/newuidmap", pid, map_file, err);
}

int
libcrun_set_usernamespace (libcrun_container *container, pid_t pid, libcrun_error_t *err)
{
#define MAX_MAPPINGS 5
  cleanup_free char *groups_file = NULL;
  cleanup_free char *uid_map_file = NULL;
  cleanup_free char *gid_map_file = NULL;
  cleanup_free char *uid_map = NULL;
  cleanup_free char *gid_map = NULL;
  int uid_map_len, gid_map_len;
  int ret;
  oci_container *def = container->container_def;

  if ((get_private_data (container)->unshare_flags & CLONE_NEWUSER) == 0)
    return 0;

  if (!def->linux->uid_mappings_len)
    {
      uid_map_len = format_default_id_mapping (&uid_map, container->container_uid, container->host_uid, 1);
      if (uid_map == NULL)
        uid_map_len = xasprintf (&uid_map, "%d %d 1", container->container_uid, container->host_uid);
    }
  else
    {
      size_t written = 0, len, s;
      char buffer[128];
      uid_map = xmalloc (sizeof (buffer) * MAX_MAPPINGS + 1);
      for (s = 0; s < def->linux->uid_mappings_len && s < MAX_MAPPINGS; s++)
        {
          len = sprintf (buffer, "%d %d %d\n",
                         def->linux->uid_mappings[s]->container_id,
                         def->linux->uid_mappings[s]->host_id,
                         def->linux->uid_mappings[s]->size);
          memcpy (uid_map + written, buffer, len);
          written += len;
        }
      uid_map[written] = '\0';
      uid_map_len = written;
    }

  if (!def->linux->gid_mappings_len)
    {
      gid_map_len = format_default_id_mapping (&gid_map, container->container_gid, container->host_gid, 0);
      if (gid_map == NULL)
        gid_map_len = xasprintf (&gid_map, "%d %d 1", container->container_gid, container->host_gid);
    }
  else
    {
      size_t written = 0, len, s;
      char buffer[128];
      gid_map = xmalloc (sizeof (buffer) * MAX_MAPPINGS + 1);
      for (s = 0; s < def->linux->gid_mappings_len && s < MAX_MAPPINGS; s++)
        {
          len = sprintf (buffer, "%d %d %d\n",
                         def->linux->gid_mappings[s]->container_id,
                         def->linux->gid_mappings[s]->host_id,
                         def->linux->gid_mappings[s]->size);
          memcpy (gid_map + written, buffer, len);
          written += len;
        }
      gid_map[written] = '\0';
      gid_map_len = written;
    }

  xasprintf (&groups_file, "/proc/%d/setgroups", pid);
  ret = write_file (groups_file, "deny", 4, err);
  if (UNLIKELY (ret < 0))
    return ret;

  xasprintf (&gid_map_file, "/proc/%d/gid_map", pid);
  ret = write_file (gid_map_file, gid_map, gid_map_len, err);
  if (ret < 1 && errno == EPERM && container->host_uid)
    {
      crun_error_release (err);
      ret = newgidmap (pid, gid_map, err);
    }
  if (UNLIKELY (ret < 0))
    return ret;

  xasprintf (&uid_map_file, "/proc/%d/uid_map", pid);
  ret = write_file (uid_map_file, uid_map, uid_map_len, err);
  if (ret < 1 && errno == EPERM && container->host_uid)
    {
      crun_error_release (err);
      ret = newuidmap (pid, uid_map, err);
    }
  if (UNLIKELY (ret < 0))
    return ret;
  return 0;
}

#define CAP_TO_MASK_0(x) (1L << ((x) & 31))
#define CAP_TO_MASK_1(x) CAP_TO_MASK_0(x - 32)

struct all_caps_s
{
  unsigned long effective[2];
  unsigned long permitted[2];
  unsigned long inheritable[2];
  unsigned long ambient[2];
  unsigned long bounding[2];
};

static int
has_cap_on (int cap, long unsigned *caps)
{
  if (cap < 32)
    return CAP_TO_MASK_0 (cap) & caps[0];
  return (CAP_TO_MASK_1 (cap) & caps[1]);
}

static int
set_required_caps (struct all_caps_s *caps, int no_new_privs, libcrun_error_t *err)
{
  unsigned long cap;
  int ret;
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct data[2] = { { 0 } };

  for (cap = 0; cap <= CAP_LAST_CAP; cap++)
    if (! has_cap_on (cap, caps->bounding))
      {
        ret = prctl (PR_CAPBSET_DROP, cap, 0, 0, 0);
        if (UNLIKELY (ret < 0 && !(errno == EINVAL || errno == EPERM)))
          return crun_make_error (err, errno, "prctl drop bounding");
      }

  data[0].effective = caps->effective[0];
  data[1].effective = caps->effective[1];
  data[0].inheritable = caps->inheritable[0];
  data[1].inheritable = caps->inheritable[1];
  data[0].permitted = caps->permitted[0];
  data[1].permitted = caps->permitted[1];

  ret = capset (&hdr, data) < 0;
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "capset");

  ret = prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
  if (UNLIKELY (ret < 0 && !(errno == EINVAL || errno == EPERM)))
    return crun_make_error (err, errno, "prctl reset ambient");

  for (cap = 0; cap <= CAP_LAST_CAP; cap++)
    if (has_cap_on (cap, caps->ambient))
      {
        ret = prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0);
        if (UNLIKELY (ret < 0 && !(errno == EINVAL || errno == EPERM)))
          return crun_make_error (err, errno, "prctl ambient raise");
      }

  if (no_new_privs)
    if (UNLIKELY (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0))
      return crun_make_error (err, errno, "no new privs");

  return 0;
}

static int
read_caps (unsigned long caps[2], char **values, size_t len, libcrun_error_t *err)
{
  size_t i;
  for (i = 0; i < len; i++)
    {
      cap_value_t cap;
      if (cap_from_name (values[i], &cap) < 0)
        return crun_make_error (err, 0, "unknown cap: %s", values[i]);
      if (cap < 32)
          caps[0] |= CAP_TO_MASK_0 (cap);
      else
          caps[1] |= CAP_TO_MASK_1 (cap);
    }
  return 0;
}

int
libcrun_set_selinux_exec_label (libcrun_container *container, libcrun_error_t *err)
{
  char *label = container->container_def->process->selinux_label;
  if (label == NULL)
    return 0;
  return set_selinux_exec_label (label, err);
}

int
libcrun_set_caps (libcrun_container *container, int keep_setuid, libcrun_error_t *err)
{
  int ret;
  struct all_caps_s caps;
  oci_container *def = container->container_def;
  memset (&caps, 0, sizeof (caps));
  if (def->process->capabilities)
    {
      ret = read_caps (caps.effective,
                       def->process->capabilities->effective,
                       def->process->capabilities->effective_len,
                       err);
      if (ret < 0)
        return ret;

      ret = read_caps (caps.inheritable,
                       def->process->capabilities->inheritable,
                       def->process->capabilities->inheritable_len,
                       err);
      if (ret < 0)
        return ret;

      ret = read_caps (caps.ambient,
                       def->process->capabilities->ambient,
                       def->process->capabilities->ambient_len,
                       err);
      if (ret < 0)
        return ret;

      ret = read_caps (caps.bounding,
                       def->process->capabilities->bounding,
                       def->process->capabilities->bounding_len,
                       err);
      if (ret < 0)
        return ret;

      ret = read_caps (caps.permitted,
                       def->process->capabilities->permitted,
                       def->process->capabilities->permitted_len,
                       err);
      if (ret < 0)
        return ret;
    }
  if (keep_setuid)
    {
      unsigned int mask = CAP_TO_MASK_0 (CAP_SETUID) | CAP_TO_MASK_0 (CAP_SETGID) | CAP_TO_MASK_0 (CAP_SETPCAP);
      caps.effective[0] |= mask;
      caps.inheritable[0] |= mask;
      caps.ambient[0] |= mask;
      caps.bounding[0] |= mask;
      caps.permitted[0] |= mask;
    }
  ret = prctl (PR_SET_KEEPCAPS, 1, 0, 0, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error while setting PR_SET_KEEPCAPS");

  return set_required_caps (&caps, def->process->no_new_privileges, err);
}

struct rlimit_s
{
  const char *name;
  int value;
};

struct rlimit_s rlimits[] =
  {
    {"RLIMIT_AS", RLIMIT_AS},
    {"RLIMIT_CORE", RLIMIT_CORE},
    {"RLIMIT_CPU", RLIMIT_CPU},
    {"RLIMIT_DATA", RLIMIT_DATA},
    {"RLIMIT_FSIZE", RLIMIT_FSIZE},
    {"RLIMIT_LOCKS", RLIMIT_LOCKS},
    {"RLIMIT_MEMLOCK", RLIMIT_MEMLOCK},
    {"RLIMIT_MSGQUEUE", RLIMIT_MSGQUEUE},
    {"RLIMIT_NICE", RLIMIT_NICE},
    {"RLIMIT_NOFILE", RLIMIT_NOFILE},
    {"RLIMIT_NPROC", RLIMIT_NPROC},
    {"RLIMIT_RSS", RLIMIT_RSS},
    {"RLIMIT_RTPRIO", RLIMIT_RTPRIO},
    {"RLIMIT_RTTIME", RLIMIT_RTTIME},
    {"RLIMIT_SIGPENDING", RLIMIT_SIGPENDING},
    {"RLIMIT_STACK", RLIMIT_STACK},
    {NULL, 0}
  };

static int
get_rlimit_resource (const char *name)
{
  struct rlimit_s *it;
  for (it = rlimits; it->name; it++)
    if (strcmp (it->name, name) == 0)
      return it->value;
  return -1;
}

int
libcrun_set_rlimits (libcrun_container *container, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  size_t i;
  if (def->process->rlimits == NULL)
    return 0;
  for (i = 0; i < def->process->rlimits_len; i++)
    {
      struct rlimit limit;
      char *type = def->process->rlimits[i]->type;
      int resource = get_rlimit_resource (type);
      if (UNLIKELY (resource < 0))
        return crun_make_error (err, errno, "invalid rlimit '%s'", type);
      limit.rlim_cur = def->process->rlimits[i]->soft;
      limit.rlim_max = def->process->rlimits[i]->hard;
      if (UNLIKELY (setrlimit (resource, &limit) < 0))
        return crun_make_error (err, errno, "setrlimit '%s'", type);
    }
  return 0;
}

int
libcrun_set_hostname (libcrun_container *container, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int has_uts = get_private_data (container)->unshare_flags & CLONE_NEWUTS;
  int ret;
  if (def->hostname == NULL || def->hostname[0] == '\0')
    return 0;
  if (!has_uts)
    return crun_make_error (err, 0, "hostname requires the UTS namespace");
  ret = sethostname (def->hostname, strlen (def->hostname));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sethostname");
  return 0;
}

int
libcrun_set_oom (libcrun_container *container, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  cleanup_close int fd = -1;
  int ret;
  char oom_buffer[16];
  if (def->process->oom_score_adj == 0)
    return 0;
  sprintf (oom_buffer, "%i", def->process->oom_score_adj);
  fd = open ("/proc/self/oom_score_adj", O_WRONLY);
  if (fd < 0)
    return crun_make_error (err, errno, "read /proc/self/oom_score_adj");
  ret = write (fd, oom_buffer, strlen (oom_buffer));
  if (ret < 0)
    return crun_make_error (err, errno, "write to /proc/self/oom_score_adj");
  return 0;
}

int
libcrun_set_sysctl (libcrun_container *container, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  size_t i;
  cleanup_close int dirfd = -1;

  if (!def->linux || !def->linux->sysctl)
    return 0;

  dirfd = open ("/sys/fs", O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open /sys/fs");

  for (i = 0; i < def->linux->sysctl->len; i++)
    {
      cleanup_free char *name = xstrdup (def->linux->sysctl->keys[i]);
      cleanup_close int fd = -1;
      int ret;
      char *it;
      for (it = name; *it; it++)
        if (*it == '.')
          *it = '/';

      fd = openat (dirfd, name, O_WRONLY);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open /sys/fs/%s", name);

      ret = write (fd, def->linux->sysctl->values[i], strlen (def->linux->sysctl->values[i]));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write to /sys/fs/%s", name);
    }
  return 0;
}

static int
open_terminal (char **slave, libcrun_error_t *err)
{
  int ret;
  cleanup_close int fd = -1;

  fd = libcrun_new_terminal (slave, err);
  if (UNLIKELY (fd < 0))
    return fd;

  ret = libcrun_set_stdio (*slave, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = fd;
  fd = -1;
  return ret;
}

int
libcrun_set_terminal (libcrun_container *container, libcrun_error_t *err)
{
  int ret;
  cleanup_close int fd = -1;
  cleanup_free char *slave = NULL;
  oci_container *def = container->container_def;
  if (!def->process->terminal)
    return 0;

  fd = open_terminal (&slave, err);
  if (UNLIKELY (fd < 0))
    return fd;

  ret = libcrun_set_stdio (slave, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process->console_size)
    {
      ret = libcrun_terminal_setup_size (0, def->process->console_size->height,
                                         def->process->console_size->width,
                                         err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (def->process->console_size)
    {
      ret = libcrun_terminal_setup_size (0, def->process->console_size->height,
                                         def->process->console_size->width,
                                         err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = write_file ("/dev/console", NULL, 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = do_mount (container, slave, "/dev/console", "devpts", MS_BIND, NULL, 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = fd;
  fd = -1;

  return ret;
}

pid_t
libcrun_run_linux_container (libcrun_container *container,
                             int detach,
                             container_entrypoint_t entrypoint,
                             void *args,
                             int *notify_socket_out,
                             int *sync_socket_out,
                             libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  size_t i;
  int ret;
  int flags = 0;
  pid_t pid;
  cleanup_close int sync_socket_host = -1;
  cleanup_close int sync_socket_container = -1;
  int sync_socket[2];

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value = find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_make_error (err, 0, "invalid namespace type: %s", def->linux->namespaces[i]->type);
      flags |= value;
    }

  if (container->host_uid && (flags & CLONE_NEWUSER) == 0)
    return crun_make_error (err, 0, "non root user need to have an 'user' namespace");

  get_private_data (container)->unshare_flags = flags;

  ret = socketpair (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sync_socket);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "socketpair");

  sync_socket_host = sync_socket[0];
  sync_socket_container = sync_socket[1];

  ret = do_notify_socket (container, notify_socket_out, def->root->path, err);
  if (UNLIKELY (ret < 0))
    return ret;

  pid = syscall_clone (flags | (detach ? 0 : SIGCHLD), NULL);
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "clone");

  get_uid_gid_from_def (container->container_def,
                        &container->container_uid,
                        &container->container_gid);

  if (pid)
    {
      ret = close (sync_socket_container);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "close");
      sync_socket_container = -1;

      if (flags & CLONE_NEWUSER)
        {
          ret = libcrun_set_usernamespace (container, pid, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = TEMP_FAILURE_RETRY (write (sync_socket_host, "1", 1));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write to sync socket");
        }

      *sync_socket_out = sync_socket_host;
      sync_socket_host = -1;

      return pid;
    }

  ret = close (sync_socket_host);
  if (UNLIKELY (ret < 0))
    {
      crun_make_error (err, errno, "close");
      goto out;
    }
  sync_socket_host = -1;

  if (detach && setsid () < 0)
    {
      crun_make_error (err, errno, "setsid");
      goto out;
    }

  /* In the container.  Join namespaces if asked and jump into the entrypoint function.  */
  if (container->host_uid == 0 && !(flags & CLONE_NEWUSER))
    {
      gid_t *additional_gids = NULL;
      size_t additional_gids_len = 0;
      if (def->process->user)
        {
          additional_gids = def->process->user->additional_gids;
          additional_gids_len = def->process->user->additional_gids_len;
        }

      ret = setgroups (additional_gids_len, additional_gids);
      if (UNLIKELY (ret < 0))
        {
          crun_make_error (err, errno, "setgroups");
          goto out;
        }
    }

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value;
      cleanup_close int fd = -1;
      if (def->linux->namespaces[i]->path == NULL)
        continue;

      value = find_namespace (def->linux->namespaces[i]->type);
      fd = open (def->linux->namespaces[i]->path, O_RDONLY);
      if (UNLIKELY (fd < 0))
        {
          crun_make_error (err, errno, "open '%s'", def->linux->namespaces[i]->path);
          goto out;
        }

      if (UNLIKELY (setns (fd, value) < 0))
        {
          crun_make_error (err, errno, "setns '%s'", def->linux->namespaces[i]->path);
          goto out;
        }
    }

  if (flags & CLONE_NEWUSER)
    {
      char tmp;
      ret = TEMP_FAILURE_RETRY (read (sync_socket_container, &tmp, 1));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "read from sync socket");
    }

  entrypoint (args, container->context->notify_socket, sync_socket_container, err);

  /* ENTRYPOINT returns only on an error, fallback here: */

 out:
  libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
  return 1;
}

static int
join_process_parent_helper (int sync_socket_fd,
                            libcrun_container_status_t *status,
                            int *terminal_fd,
                            libcrun_error_t *err)
{
  int ret;
  char res;
  pid_t pid;
  cleanup_close int sync_fd = sync_socket_fd;

  if (terminal_fd)
    *terminal_fd = -1;

  /* Read the status and the PID from the child process.  */
  ret = TEMP_FAILURE_RETRY (read (sync_fd, &res, 1));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read from sync socket");

  if (res != '0')
    return crun_make_error (err, 0, "fail startup");

  ret = TEMP_FAILURE_RETRY (read (sync_fd, &pid, sizeof (pid)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read from sync socket");

  ret = libcrun_move_process_to_cgroup (pid, status->cgroup_path, err);
  /* The write unblocks the grandchild process so it can run once we setup
     the cgroups.  */
  ret = TEMP_FAILURE_RETRY (write (sync_fd, &ret, sizeof (ret)));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write to sync socket");

  if (terminal_fd)
    {
      ret = receive_fd_from_socket (sync_fd, err);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "receive fd");
      *terminal_fd = ret;
    }

  return pid;
}

int
libcrun_join_process (pid_t pid_to_join, libcrun_container_status_t *status, int detach, int *terminal_fd, libcrun_error_t *err)
{
  pid_t pid;
  int ret;
  int sync_socket_fd[2];
  int fds[10] = {-1, };
  int namespaces_id[] = {CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNS, CLONE_NEWNET, CLONE_NEWPID, CLONE_NEWUTS, CLONE_NEWUSER, 0};
  const char *namespaces[] = {"cgroup", "ipc", "mnt",  "net", "pid", "uts", "user", NULL};
  size_t i;
  cleanup_close int sync_fd = -1;

  ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "set child subreaper");

  ret = socketpair (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sync_socket_fd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error creating socketpair");

  pid = fork ();
  if (UNLIKELY (pid < 0))
    {
      crun_make_error (err, errno, "fork");
      goto exit;
    }
  if (pid)
    {
      close (sync_socket_fd[1]);
      return join_process_parent_helper (sync_socket_fd[0], status, terminal_fd, err);
    }

  close (sync_socket_fd[0]);
  sync_fd = sync_socket_fd[1];

  for (i = 0; namespaces[i]; i++)
    {
      cleanup_close int fd = -1;
      cleanup_free char *ns_join;
      xasprintf (&ns_join, "/proc/%d/ns/%s", pid_to_join, namespaces[i]);
      fds[i] = open (ns_join, O_RDONLY);
      if (UNLIKELY (fds[i] < 0))
        {
          ret = crun_make_error (err, errno, "open '%s'", ns_join);
          goto exit;
        }
    }

  for (i = 0; namespaces[i]; i++)
    {
      ret = setns (fds[i], namespaces_id[i]);
      if (ret > 0)
        fds[i] = -1;
    }
  for (i = 0; namespaces[i]; i++)
    {
      if (fds[i] < 0)
        continue;
      ret = setns (fds[i], namespaces_id[i]);
      if (UNLIKELY (ret < 0 && errno != EINVAL))
        {
          crun_make_error (err, errno, "setns '%s'", namespaces[i]);
          goto exit;
        }
      fds[i] = -1;
    }
  for (i = 0; namespaces[i]; i++)
    {
      close (fds[i]);
      fds[i] = -1;
    }

  if (detach && setsid () < 0)
    {
      crun_make_error (err, errno, "setsid");
      goto exit;
    }

  /* We need to fork once again to join the PID namespace.  */
  pid = fork ();
  if (UNLIKELY (pid < 0))
    {
      ret = TEMP_FAILURE_RETRY (write (sync_fd, "1", 1));
      crun_make_error (err, errno, "fork");
      goto exit;
    }

  if (pid)
    {
      /* Just return the PID to the parent helper and exit.  */
      ret = TEMP_FAILURE_RETRY (write (sync_fd, "0", 1));
      ret = TEMP_FAILURE_RETRY (write (sync_fd, &pid, sizeof (pid)));
      _exit (0);
    }
  else
    {
      /* Inside the grandchild process.  The real process
         used for the container.  */
      int r = -1;
      cleanup_free char *slave = NULL;
      cleanup_close int master_fd = -1;

      ret = TEMP_FAILURE_RETRY (read (sync_fd, &r, sizeof (r)));

      if (terminal_fd)
        {
          if (setsid () < 0)
            libcrun_fail_with_error (errno, "setsid");

          master_fd = open_terminal (&slave, err);
          if (UNLIKELY (master_fd < 0))
            {
              crun_error_write_warning_and_release (stderr, err);
              _exit (1);
            }

          ret = send_fd_to_socket (sync_fd, master_fd, err);
          if (UNLIKELY (ret < 0))
            {
              crun_error_write_warning_and_release (stderr, err);
              _exit (1);
            }
        }

      if (r != 0)
        _exit (1);
    }

  return pid;

 exit:
  if (sync_socket_fd[0] >= 0)
    close (sync_socket_fd[0]);
  if (sync_socket_fd[1] >= 0)
    close (sync_socket_fd[1]);
  for (i = 0; namespaces[i]; i++)
    if (fds[i] >= 0)
      close (fds[i]);
  return ret;
}
