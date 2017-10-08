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
#include "cgroup.h"
#include "utils.h"
#include <string.h>
#include <sys/types.h>
#include <systemd/sd-bus.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libgen.h>

static const char *subsystems[] = { "cpuset", "devices", "pids", "memory",
                                    "net_cls,net_prio", "freezer", "blkio",
                                    "hugetlb", "cpu,cpuacct", "perf_event",
                                    "unified", NULL};

static int
initialize_cpuset_subsystem (const char *path, libcrun_error_t *err)
{
  int ret;
  size_t i;
  cleanup_free char *parentdir_path_buf = NULL;
  char *parent_dir_path = NULL;
  cleanup_close int dirfd = -1;
  cleanup_close int parent_dirfd = -1;
  const char *files[2] = {"cpuset.cpus", "cpuset.mems"};

  parentdir_path_buf = xstrdup (path);
  parent_dir_path = dirname (parentdir_path_buf);

  dirfd = open (path, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open '%s'", path);

  parent_dirfd = open (parent_dir_path, O_DIRECTORY | O_RDONLY);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open '%s'", parent_dir_path);

  for (i = 0; i < 2; i++)
    {
      char b[256];
      ssize_t b_len;
      cleanup_close int fd = openat (parent_dirfd, files[i], O_RDWR);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open '%s/%s'", parent_dir_path, files[i]);

      b_len = TEMP_FAILURE_RETRY (read (fd, b, sizeof (b)));
      if (UNLIKELY (b_len < 0))
        return crun_make_error (err, errno, "read from '%s/%s'", parent_dir_path, files[i]);

      /* Write to the parent only if not already configured.  */
      if (b_len == 0 || (b_len == 1 && b[0] == '\n'))
        {
          strcpy (b, "0\n");
          b_len = 2;
          ret = TEMP_FAILURE_RETRY (write (fd, b, b_len));
          if (UNLIKELY (ret < 0))
            return ret;

        }

      ret = write_file_at (dirfd, files[i], b, b_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
enter_cgroup (pid_t pid, const char *path, int ensure_missing, libcrun_error_t *err)
{
  char pid_str[16];
  int ret;
  size_t i;

  sprintf (pid_str, "%d", pid);

  for (i = 0; subsystems[i]; i++)
    {
      cleanup_free char *cgroup_path = NULL;
      cleanup_free char *cgroup_path_procs = NULL;

      xasprintf (&cgroup_path, "/sys/fs/cgroup/%s%s", subsystems[i], path);

      if (ensure_missing)
        {
          ret = crun_ensure_directory (cgroup_path, 0755, err);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "creating cgroup directory '%s'", cgroup_path);

          if (strcmp (subsystems[i], "cpuset") == 0)
            {
              ret = initialize_cpuset_subsystem (cgroup_path, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
        }
      else
        {
          ret = crun_path_exists (cgroup_path, 0, err);
          if (UNLIKELY (ret < 0))
            return ret;
          if (ret == 0)
            continue;
        }

      xasprintf (&cgroup_path_procs, "/sys/fs/cgroup/%s/%s/cgroup.procs", subsystems[i], path);
      ret = write_file (cgroup_path_procs, pid_str, strlen (pid_str), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

int
libcrun_move_process_to_cgroup (pid_t pid, char *path, libcrun_error_t *err)
{
  return enter_cgroup (pid, path, 0, err);
}

static
int get_system_path (char **path, const char *suffix, libcrun_error_t *err)
{
  xasprintf (path, "/system.slice/libcrun-%s", suffix);
  return 0;
}

static
int get_current_path (char **path, pid_t pid, const char *suffix, libcrun_error_t *err)
{
  cleanup_free char *content = NULL;
  int ret;
  char *from, *to;
  cleanup_free char *cgroup_path = NULL;

  xasprintf (&cgroup_path, "/proc/%d/cgroup", pid);
  ret = read_all_file (cgroup_path, &content, NULL, err);
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
int enter_systemd_cgroup_scope (char **path, const char *scope, pid_t pid, libcrun_error_t *err)
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
libcrun_cgroup_enter (char **path, const char *cgroup_path, int systemd, pid_t pid, const char *id, libcrun_error_t *err)
{
  int ret;
  cleanup_free char *scope;
  xasprintf (&scope, "%s.scope", id);

  if (systemd || getuid ())
    {
      ret = enter_systemd_cgroup_scope (path, scope, pid, err);
      if (UNLIKELY (ret < 0))
        return ret;
      return get_current_path (path, pid, NULL, err);
    }
  else
    {
      if (cgroup_path != NULL)
        *path = xstrdup (cgroup_path);
      else
        {
          ret = get_system_path (path, scope, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      return enter_cgroup (pid, *path, 1, err);
    }
  return 0;
}


int
libcrun_cgroup_killall (char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path_procs = NULL;
  cleanup_free char *buffer = NULL;
  int ret;
  size_t len;
  char *it;
  char *saveptr = NULL;

  xasprintf (&cgroup_path_procs, "/sys/fs/cgroup/unified/%s/cgroup.procs", path);
  ret = read_all_file (cgroup_path_procs, &buffer, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  for (it = strtok_r (buffer, "\n", &saveptr); it; it = strtok_r (NULL, "\n", &saveptr))
    {
      pid_t pid = strtoul (it, NULL, 10);
      if (pid)
        {
          ret = kill (pid, 9);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "kill process %d", pid);
        }
    }

  return 0;
}

static void
kill_all_processes (char *cgroup_path)
{
  libcrun_error_t err = NULL;
  cleanup_free char *buffer = NULL;
  size_t len;
  int ret;
  cleanup_free char *cgroup_procs_path = NULL;
  char *it;
  char *saveptr = NULL;

  xasprintf (&cgroup_procs_path, "%s/%s", cgroup_path, "cgroup.procs");

  ret = read_all_file (cgroup_procs_path, &buffer, &len, &err);
  if (UNLIKELY (ret < 0))
    {
      crun_error_release (&err);
      return;
    }

  for (it = strtok_r (buffer, "\n", &saveptr); it; it = strtok_r (NULL, "\n", &saveptr))
    {
      pid_t pid = strtoull (it, NULL, 10);
      kill (pid, 9);
    }
}

int
libcrun_cgroup_destroy (char *path, libcrun_error_t *err)
{
  int ret;
  size_t i;

  for (i = 0; subsystems[i]; i++)
    {
      cleanup_free char *cgroup_path;
      xasprintf (&cgroup_path, "/sys/fs/cgroup/%s/%s", subsystems[i], path);

      ret = crun_path_exists (cgroup_path, 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret == 0)
        continue;

      kill_all_processes (cgroup_path);

      ret = rmdir (cgroup_path);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "deleting cgroup '%s'", path);
    }

  return 0;
}

/* The parser generates different structs but they are really all the same.  */
struct throttling_s
{
    int64_t major;
    int64_t minor;
    uint64_t rate;
};

static int
write_blkio_resources_throttling (int dirfd, const char *name, struct throttling_s **throttling, size_t throttling_len, libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i;
  cleanup_close int fd = -1;

  fd = openat (dirfd, name, O_WRONLY);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open %s", name);

  for (i = 0; i < throttling_len; i++)
    {
      int ret;
      size_t len;
      len = sprintf (fmt_buf, "%lu:%lu %lu\n",
                     throttling[i]->major,
                     throttling[i]->minor,
                     throttling[i]->rate);

      ret = write (fd, fmt_buf, len);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write %s", name);
    }
  return 0;
}

static int
write_blkio_resources (int dirfd, oci_container_linux_resources_block_io *blkio, libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;
  size_t i;

  if (blkio->weight)
    {
      len = sprintf (fmt_buf, "%d", blkio->weight);
      ret = write_file_at (dirfd, "blkio.weight", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->leaf_weight)
    {
      len = sprintf (fmt_buf, "%d", blkio->leaf_weight);
      ret = write_file_at (dirfd, "blkio.leaf_weight", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->weight_device_len)
    {
      cleanup_close int w_device_fd = -1;
      cleanup_close int w_leafdevice_fd = -1;

      w_device_fd = openat (dirfd, "blkio.weight_device", O_WRONLY);
      if (UNLIKELY (w_device_fd < 0))
        return crun_make_error (err, errno, "open blkio.weight_device");

      w_leafdevice_fd = openat (dirfd, "blkio.leaf_weight_device", O_WRONLY);
      if (UNLIKELY (w_leafdevice_fd < 0))
        return crun_make_error (err, errno, "open blkio.leaf_weight_device");

      for (i = 0; i < blkio->weight_device_len; i++)
        {
          len = sprintf (fmt_buf, "%lu:%lu %i\n",
                         blkio->weight_device[i]->major,
                         blkio->weight_device[i]->minor,
                         blkio->weight_device[i]->weight);
          ret = write (w_device_fd, fmt_buf, len);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write blkio.weight_device");

          len = sprintf (fmt_buf, "%lu:%lu %i\n",
                         blkio->weight_device[i]->major,
                         blkio->weight_device[i]->minor,
                         blkio->weight_device[i]->leaf_weight);
          ret = write (w_leafdevice_fd, fmt_buf, len);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write blkio.leaf_weight_device");
        }
    }
  if (blkio->throttle_read_bps_device_len)
    {
      ret = write_blkio_resources_throttling (dirfd, "blkio.throttle.read_bps_device",
                                              (struct throttling_s **) blkio->throttle_read_bps_device,
                                              blkio->throttle_read_bps_device_len,
                                              err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->throttle_write_bps_device_len)
    {
      ret = write_blkio_resources_throttling (dirfd, "blkio.throttle.write_bps_device",
                                              (struct throttling_s **) blkio->throttle_write_bps_device,
                                              blkio->throttle_write_bps_device_len,
                                              err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->throttle_read_iops_device_len)
    {
      ret = write_blkio_resources_throttling (dirfd, "blkio.throttle.read_iops_device",
                                              (struct throttling_s **) blkio->throttle_read_iops_device,
                                              blkio->throttle_read_iops_device_len,
                                              err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (blkio->throttle_write_iops_device_len)
    {
      ret = write_blkio_resources_throttling (dirfd, "blkio.throttle.write_iops_device",
                                              (struct throttling_s **) blkio->throttle_write_iops_device,
                                              blkio->throttle_write_iops_device_len,
                                              err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_network_resources (int dirfd, oci_container_linux_resources_network *net, libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t len;
  int ret;
  if (net->class_id)
    {
      len = sprintf (fmt_buf, "%d", net->class_id);
      ret = write_file_at (dirfd, "net_cls.classid", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (net->priorities_len)
    {
      size_t i;
      cleanup_close int fd = -1;
      fd = openat (dirfd, "net_prio.ifpriomap", O_WRONLY);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "open net_prio.ifpriomap");

      for (i = 0; i < net->priorities_len; i++)
        {
          sprintf (fmt_buf, "%s %d\n", net->priorities[i]->name, net->priorities[i]->priority);
          ret = write (fd, fmt_buf, len);
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write net_prio.ifpriomap");
        }

    }

  return 0;
}

static int
write_hugetlb_resources (int dirfd, oci_container_linux_resources_hugepage_limits_element **htlb, size_t htlb_len, libcrun_error_t *err)
{
  char fmt_buf[128];
  size_t i, len;
  int ret;
  for (i = 0; i < htlb_len; i++)
    {
      cleanup_free char *filename;
      xasprintf (&filename, "hugetlb.%s.limit_in_bytes", htlb[i]->page_size);

      len = sprintf (fmt_buf, "%lu", htlb[i]->limit);
      ret = write_file_at (dirfd, filename, fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_devices_resources (int dirfd, oci_container_linux_resources_devices_element **devs, size_t devs_len, libcrun_error_t *err)
{
  size_t i, len;
  int ret;
  for (i = 0; i < devs_len; i++)
    {
      cleanup_free char *fmt_buf;
      const char *file = devs[i]->allow ? "devices.allow" : "devices.deny";

      if (devs[i]->type == NULL || devs[i]->type[0] == 'a')
        len = xasprintf (&fmt_buf, "a");
      else
        len = xasprintf (&fmt_buf, "%s %lu:%lu %s", devs[i]->type, devs[i]->major, devs[i]->minor, devs[i]->access);
      ret = write_file_at (dirfd, file, fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_memory_resources (int dirfd, oci_container_linux_resources_memory *memory, libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[32];
  char swap_buf[32];
  char limit_buf[32];
  size_t swap_buf_len, limit_buf_len;
  swap_buf_len = sprintf (swap_buf, "%lu", memory->swap);
  limit_buf_len = sprintf (limit_buf, "%lu", memory->limit);

  if (memory->limit && memory->swap)
    {
      if (memory->limit < memory->swap)
        {
          ret = write_file_at (dirfd, "memory.memsw.limit_in_bytes", swap_buf, swap_buf_len, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = write_file_at (dirfd, "memory.limit_in_bytes", limit_buf, limit_buf_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          ret = write_file_at (dirfd, "memory.limit_in_bytes", limit_buf, limit_buf_len, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = write_file_at (dirfd, "memory.memsw.limit_in_bytes", swap_buf, swap_buf_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }
  else
    {
      if (memory->swap)
        {
          ret = write_file_at (dirfd, "memory.memsw.limit_in_bytes", swap_buf, swap_buf_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      if (memory->limit)
        {
          ret = write_file_at (dirfd, "memory.limit_in_bytes", limit_buf, limit_buf_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

    }

  if (memory->kernel)
    {
      len = sprintf (fmt_buf, "%lu", memory->swappiness);
      ret = write_file_at (dirfd, "memory.kmem.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memory->reservation)
    {
      len = sprintf (fmt_buf, "%lu", memory->reservation);
      ret = write_file_at (dirfd, "memory.soft_limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->disable_oom_killer)
    {
      ret = write_file_at (dirfd, "memory.oom_control", "1", 1, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->kernel_tcp)
    {
      len = sprintf (fmt_buf, "%lu", memory->kernel_tcp);
      ret = write_file_at (dirfd, "memory.kmem.tcp.limit_in_bytes", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (memory->swappiness)
    {
      len = sprintf (fmt_buf, "%lu", memory->swappiness);
      ret = write_file_at (dirfd, "memory.swappiness", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_pids_resources (int dirfd, oci_container_linux_resources_pids *pids, libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[32];

  if (pids->limit)
    {
      len = sprintf (fmt_buf, "%lu", pids->limit);
      ret = write_file_at (dirfd, "pids.max", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
write_cpu_resources (int dirfd_cpu, oci_container_linux_resources_cpu *cpu, libcrun_error_t *err)
{
  size_t len;
  int ret;
  char fmt_buf[32];

  if (cpu->shares)
    {
      len = sprintf (fmt_buf, "%lu", cpu->shares);
      ret = write_file_at (dirfd_cpu, "cpu.shares", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->period)
    {
      len = sprintf (fmt_buf, "%lu", cpu->period);
      ret = write_file_at (dirfd_cpu, "cpu.cfs_period_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->quota)
    {
      len = sprintf (fmt_buf, "%lu", cpu->quota);
      ret = write_file_at (dirfd_cpu, "cpu.cfs_quota_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->realtime_period)
    {
      len = sprintf (fmt_buf, "%lu", cpu->realtime_period);
      ret = write_file_at (dirfd_cpu, "cpu.rt_period_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->realtime_runtime)
    {
      len = sprintf (fmt_buf, "%lu", cpu->realtime_runtime);
      ret = write_file_at (dirfd_cpu, "cpu.rt_runtime_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
write_cpuset_resources (int dirfd_cpuset, oci_container_linux_resources_cpu *cpu, libcrun_error_t *err)
{
  int ret;
  if (cpu->cpus)
    {
      ret = write_file_at (dirfd_cpuset, "cpuset.cpus", cpu->cpus, strlen (cpu->cpus), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  if (cpu->mems)
    {
      ret = write_file_at (dirfd_cpuset, "cpuset.mems", cpu->mems, strlen (cpu->mems), err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

int
libcrun_set_cgroup_resources (libcrun_container *container, char *path, FILE *stderr, libcrun_error_t *err)
{
  oci_container *def = container->container_def;
  int ret;

  if (!def->linux || !def->linux->resources)
    return 0;

#define SKIP(ret, errno)(ret < 0 && errno == ENOENT && getuid ())
  if (def->linux->resources->block_io)
    {
      cleanup_free char *path_to_blkio = NULL;
      cleanup_close int dirfd_blkio = -1;
      oci_container_linux_resources_block_io *blkio = def->linux->resources->block_io;

      xasprintf (&path_to_blkio, "/sys/fs/cgroup/blkio%s/", path);
      dirfd_blkio = open (path_to_blkio, O_DIRECTORY | O_RDONLY);
      if (SKIP (dirfd_blkio, errno))
        libcrun_warning (stderr, "skip block IO resources specified since there is no cgroup available");
      else
        {
          if (UNLIKELY (dirfd_blkio < 0))
            return crun_make_error (err, errno, "open /sys/fs/cgroup/blkio%s", path);

          ret = write_blkio_resources (dirfd_blkio, blkio, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  if (def->linux->resources->network)
    {
      cleanup_free char *path_to_network = NULL;
      cleanup_close int dirfd_network = -1;
      oci_container_linux_resources_network *network = def->linux->resources->network;

      xasprintf (&path_to_network, "/sys/fs/cgroup/net_cls,net_prio%s/", path);
      dirfd_network = open (path_to_network, O_DIRECTORY | O_RDONLY);
      if (SKIP (dirfd_network, errno))
        libcrun_warning (stderr, "skip network resources specified since there is no cgroup available");
      else
        {
          if (UNLIKELY (dirfd_network < 0))
            return crun_make_error (err, errno, "open /sys/fs/cgroup/net_cls,net_prio%s", path);

          ret = write_network_resources (dirfd_network, network, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  if (def->linux->resources->hugepage_limits_len)
    {
      cleanup_free char *path_to_htlb = NULL;
      cleanup_close int dirfd_htlb = -1;

      xasprintf (&path_to_htlb, "/sys/fs/cgroup/hugetlb%s/", path);
      dirfd_htlb = open (path_to_htlb, O_DIRECTORY | O_RDONLY);
      if (SKIP (dirfd_htlb, errno))
        libcrun_warning (stderr, "hugetlb resources specified since there is no cgroup available");
      else
        {
          if (UNLIKELY (dirfd_htlb < 0))
            return crun_make_error (err, errno, "open /sys/fs/cgroup/hugetlb%s", path);

          ret = write_hugetlb_resources (dirfd_htlb,
                                         def->linux->resources->hugepage_limits,
                                         def->linux->resources->hugepage_limits_len,
                                         err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  if (def->linux->resources->devices_len)
    {
      cleanup_free char *path_to_devs = NULL;
      cleanup_close int dirfd_devs = -1;

      xasprintf (&path_to_devs, "/sys/fs/cgroup/devices%s/", path);
      dirfd_devs = open (path_to_devs, O_DIRECTORY | O_RDONLY);
      if (SKIP (dirfd_devs, errno))
        libcrun_warning (stderr, "skip devices resources specified since there is no cgroup available");
      else
        {
          if (UNLIKELY (dirfd_devs < 0))
            return crun_make_error (err, errno, "open /sys/fs/cgroup/devices%s", path);

          ret = write_devices_resources (dirfd_devs,
                                         def->linux->resources->devices,
                                         def->linux->resources->devices_len,
                                         err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  if (def->linux->resources->memory)
    {
      cleanup_free char *path_to_mem = NULL;
      cleanup_close int dirfd_mem = -1;

      xasprintf (&path_to_mem, "/sys/fs/cgroup/memory%s/", path);
      dirfd_mem = open (path_to_mem, O_DIRECTORY | O_RDONLY);
      if (SKIP (dirfd_mem, errno))
        libcrun_warning (stderr, "skip memory resources specified since there is no cgroup available");
      else
        {
          if (UNLIKELY (dirfd_mem < 0))
            return crun_make_error (err, errno, "open /sys/fs/cgroup/memory%s", path);

          ret = write_memory_resources (dirfd_mem,
                                        def->linux->resources->memory,
                                        err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  if (def->linux->resources->pids)
    {
      cleanup_free char *path_to_pid = NULL;
      cleanup_close int dirfd_pid = -1;

      xasprintf (&path_to_pid, "/sys/fs/cgroup/pids%s/", path);
      dirfd_pid = open (path_to_pid, O_DIRECTORY | O_RDONLY);
      if (SKIP (dirfd_pid, errno))
        libcrun_warning (stderr, "skip pids resources specified since there is no cgroup available");
      else
        {
          if (UNLIKELY (dirfd_pid < 0))
            return crun_make_error (err, errno, "open %s", path);

          ret = write_pids_resources (dirfd_pid,
                                      def->linux->resources->pids,
                                      err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  if (def->linux->resources->cpu)
    {
      cleanup_free char *path_to_cpu = NULL;
      cleanup_close int dirfd_cpu = -1;
      cleanup_free char *path_to_cpuset = NULL;
      cleanup_close int dirfd_cpuset = -1;

      xasprintf (&path_to_cpu, "/sys/fs/cgroup/cpu%s/", path);
      dirfd_cpu = open (path_to_cpu, O_DIRECTORY | O_RDONLY);
      if (SKIP (dirfd_cpu, errno))
        libcrun_warning (stderr, "skip cpu resources specified since there is no cgroup available");
      else
        {
          ret = write_cpu_resources (dirfd_cpu,
                                     def->linux->resources->cpu,
                                     err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      xasprintf (&path_to_cpu, "/sys/fs/cgroup/cpuset%s/", path);
      dirfd_cpuset = open (path_to_cpuset, O_DIRECTORY | O_RDONLY);
      if (SKIP (dirfd_cpuset, errno))
        libcrun_warning (stderr, "skip cpuset resources specified since there is no cgroup available");
      else
        {
          ret = write_cpuset_resources (dirfd_cpuset,
                                        def->linux->resources->cpu,
                                        err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  return 0;
}
