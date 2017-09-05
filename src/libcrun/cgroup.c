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
#include <config.h>
#include "cgroup.h"
#include "utils.h"
#include <string.h>
#include <sys/types.h>
#include <systemd/sd-bus.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

static int
enter_cgroup (pid_t pid, const char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path;
  cleanup_free char *cgroup_path_procs;
  cleanup_close int fd = -1;
  char pid_str[16];
  int ret;

  xasprintf (&cgroup_path, "/sys/fs/cgroup/unified/%s", path);

  ret = mkdir (cgroup_path, 0755);
  if (UNLIKELY (ret < 0 && errno != EEXIST))
    return crun_make_error (err, errno, "creating cgroup '%s'", path);

  xasprintf (&cgroup_path_procs, "/sys/fs/cgroup/unified/%s/cgroup.procs", path);

  fd = open (cgroup_path_procs, O_WRONLY);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "opening '%s'", cgroup_path_procs);

  sprintf (pid_str, "%d", pid);

  do
    ret = write (fd, pid_str, strlen (pid_str));
  while (ret < 0 && errno == EINTR);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "cannot write to '%s'", cgroup_path_procs);

  return 0;
}

static
int get_current_path (char **path, const char *suffix, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  int ret;
  char *from, *to;

  ret = read_all_file ("/proc/self/cgroup", &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;
  from = strstr (content, "0::");
  if (UNLIKELY (from == NULL))
    return crun_make_error (err, 0, "cannot find cgroup2 for the current process");

  from += 3;
  to = strchr (from, '\n');
  if (UNLIKELY (to == NULL))
    return crun_make_error (err, 0, "cannot parse /proc/self/cgroup");
  *to = '\0';

  if (suffix)
    xasprintf (path, "%s/%s", from, suffix);
  else
    *path = xstrdup (from);

  return 0;
}

struct systemd_job_removed_s
{
  const char *path;
  int *terminated;
};

static int
systemd_job_removed (sd_bus_message *m, void *userdata, sd_bus_error *error)
{
  const char *path, *unit, *result;
  uint32_t id;
  int ret;
  struct systemd_job_removed_s *p = userdata;
  
  ret = sd_bus_message_read (m, "uoss", &id, &path, &unit, &result);
  if (ret < 0)
    return -1;

  if (strcmp (p->path, path) == 0)
    *p->terminated = 1;
  return 0;
}

static
int enter_system_cgroup_scope (char **path, const char *scope, pid_t pid, libcrun_error_t *err)
{
  sd_bus *bus = NULL;
  sd_bus_message *m = NULL;
  sd_bus_message *reply = NULL;
  int ret = 0;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  const char *object;
  int terminated = 0;
  struct systemd_job_removed_s userdata;

  if (sd_bus_default (&bus) < 0)
    {
      ret = crun_make_error (err, 0, "cannot open sd-bus");
      goto exit;
    }

  ret = sd_bus_add_match (bus,
                          NULL,
                          "type='signal',"
                          "sender='org.freedesktop.systemd1',"
                          "interface='org.freedesktop.systemd1.Manager',"
                          "member='JobRemoved',"
                          "path='/org/freedesktop/systemd1'",
                          systemd_job_removed, &userdata);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus message read");
      goto exit;
    }

  if (UNLIKELY (sd_bus_message_new_method_call (bus, &m,
                                                "org.freedesktop.systemd1",
                                                "/org/freedesktop/systemd1",
                                                "org.freedesktop.systemd1.Manager",
                                                "StartTransientUnit") < 0))
    {
      ret = crun_make_error (err, 0, "set up dbus message");
      goto exit;
    }
  if (UNLIKELY (sd_bus_message_append (m, "ss", scope, "fail") < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus message append");
      goto exit;
    }
  
  if (UNLIKELY (sd_bus_message_open_container (m, 'a', "(sv)") < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus open container");
      goto exit;
    }

  if (UNLIKELY (sd_bus_message_append (m, "(sv)", "Description", "s", "libcrun container") < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus message append");
      goto exit;
    }

  if (UNLIKELY (sd_bus_message_append (m, "(sv)", "PIDs", "au", 1, pid) < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus message append");
      goto exit;
    }

  if (UNLIKELY (sd_bus_message_close_container (m) < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus close container");
      goto exit;
    }

  if (UNLIKELY (sd_bus_message_append (m, "a(sa(sv))", 0) < 0))
    {
      ret = crun_make_error (err, 0, "sd-bus message append");
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
      ret = crun_make_error (err, 0, "sd-bus message read");
      goto exit;
    }

  userdata.path = object;
  userdata.terminated = &terminated;
  while (!terminated)
    {
      ret = sd_bus_process (bus, NULL);
      if (UNLIKELY (ret < 0))
        {
          ret = crun_make_error (err, 0, "sd-bus process");
          break;
        }

      if (ret == 0)
        {
          ret = sd_bus_wait (bus, (uint64_t) -1);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, 0, "sd-bus wait");
              break;
            }
          continue;
        }

      if (UNLIKELY (ret < 0))
        {
          ret = crun_make_error (err, 0, "sd-bus wait");
          break;
        }
    }
  
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

int
libcrun_cgroup_enter (char **path, int systemd, pid_t pid, const char *id, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *scope;
  xasprintf (&scope, "%s.scope", id);

  if (systemd)
    {
      ret = enter_system_cgroup_scope (path, scope, pid, err);
      if (UNLIKELY (ret < 0))
        return ret;
      return get_current_path (path, NULL, err);
    }
  else
    {
      ret = get_current_path (path, scope, err);
      if (UNLIKELY (ret < 0))
        return ret;
      return enter_cgroup (pid, *path, err);
    }
  return 0;
}


int
libcrun_cgroup_killall (char *path, libcrun_error_t *err)
{
  return 0;
}

int
libcrun_cgroup_destroy (char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path;
  int ret;

  xasprintf (&cgroup_path, "/sys/fs/cgroup/unified/%s", path);

  ret = rmdir (cgroup_path);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "deleting cgroup '%s'", path);

  return 0;
}
