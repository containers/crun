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

#define _GNU_SOURCE

#include <config.h>
#include "linux.h"
#include "utils.h"
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>

struct linux_namespace_s
{
  const char *name;
  int value;
};

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


int
libcrun_set_namespaces (oci_container *def, char **err)
{
  size_t i;
  int flags = 0;
  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value = find_namespace (def->linux->namespaces[i]->type);
      if (UNLIKELY (value < 0))
        return crun_static_error (err, 0, "invalid namespace type: %s", def->linux->namespaces[i]->type);
      flags |= value;
    }

  if (UNLIKELY (unshare (flags) < 0))
    return crun_static_error (err, errno, "unshare");

  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value, fd;
      if (def->linux->namespaces[i]->path == NULL)
        continue;

      value = find_namespace (def->linux->namespaces[i]->type);
      fd = open (def->linux->namespaces[i]->path, O_RDONLY);
      if (UNLIKELY (fd < 0))
        return crun_static_error (err, errno, "open '%s'", def->linux->namespaces[i]->path);

      if (setns (fd, value) < 0)
        {
          close (fd);
          return crun_static_error (err, errno, "setns '%s'", def->linux->namespaces[i]->path);
        }

      close (fd);
    }

  return 0;
}

int
libcrun_set_mounts (oci_container *container, const char *rootfs, char **err)
{
  size_t i;
  int ret;

  ret = mount ("none", "/", NULL, MS_REC | MS_SLAVE, NULL);
  if (UNLIKELY (ret < 0))
    return crun_static_error (err, errno, "remount root");

  ret = mount (container->root->path, rootfs, "", MS_BIND | MS_REC | MS_PRIVATE, NULL);
  if (UNLIKELY (ret < 0))
    return crun_static_error (err, errno, "mount rootfs '%s'", container->mounts[i]->destination);
  for (i = 0; i < container->mounts_len; i++)
    {
      cleanup_free char *target = NULL;
      int flags = 0;
      void *data = NULL;

      if (UNLIKELY (asprintf (&target, "%s/%s", rootfs, container->mounts[i]->destination + 1) < 0))
        OOM ();

      ret = mount (container->mounts[i]->source, target, container->mounts[i]->type, flags, data);
      if (UNLIKELY (ret < 0))
        return crun_static_error (err, errno, "mount '%s'", container->mounts[i]->destination);
    }
  return 0;
}
