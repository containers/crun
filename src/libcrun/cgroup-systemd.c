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
#include "cgroup-internal.h"
#include "cgroup-systemd.h"
#include "cgroup-resources.h"
#include "cgroup-utils.h"
#include "ebpf.h"
#include "utils.h"
#include "status.h"
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/vfs.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>

#ifdef HAVE_SYSTEMD
#  include <systemd/sd-bus.h>
#  include <limits.h>

#  define SYSTEMD_PROPERTY_PREFIX "org.systemd.property."

#  define CGROUP_BFQ_WEIGHT_MIN ((uint64_t) 1)
#  define CGROUP_BFQ_WEIGHT_DEFAULT ((uint64_t) 100)
#  define CGROUP_BFQ_WEIGHT_MAX ((uint64_t) 1000)

#  define CGROUP_WEIGHT_MIN ((uint64_t) 1)
#  define CGROUP_WEIGHT_DEFAULT ((uint64_t) 100)
#  define CGROUP_WEIGHT_MAX ((uint64_t) 10000)

#  define SYSTEMD_MISSING_PROPERTIES_DIR ".cache/systemd-missing-properties"

#  define IS_WILDCARD(x) (x <= 0)

static int
register_missing_property_from_message (const char *state_dir, const char *message, libcrun_error_t *err)
{
  cleanup_free char *file_path = NULL;
  cleanup_free char *dir_path = NULL;
  cleanup_free char *property = NULL;
  char *p;
  int ret;

  if (! has_prefix (message, "Cannot set property "))
    return 0;

  property = xstrdup (message + sizeof ("Cannot set property ") - 1);
  p = strchr (property, ',');
  if (! p)
    return 0;
  *p = '\0';

  ret = append_paths (&dir_path, err, state_dir, SYSTEMD_MISSING_PROPERTIES_DIR, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = crun_ensure_directory (dir_path, 0755, true, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_paths (&file_path, err, dir_path, property, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  libcrun_debug ("Registering missing property for systemd `%s`", property);

  ret = write_file (file_path, NULL, 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return 1;
}

static bool
property_missing_p (char **missing_properties, const char *property)
{
  size_t i;

  for (i = 0; missing_properties && missing_properties[i]; i++)
    if (strcmp (missing_properties[i], property) == 0)
      {
        libcrun_debug ("Skipping property for systemd as it is not supported `%s`", property);
        return true;
      }

  return false;
}

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

/* set the rt-runtime for the current cgroup and its parent if the path is not a scope.  */
static int
setup_rt_runtime (runtime_spec_schema_config_linux_resources *resources,
                  const char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  cleanup_close int dirfd = -1;
  bool need_set_parent = true;
  char fmt_buf[64];
  size_t len;
  int ret;

  if (resources == NULL || resources->cpu == NULL)
    return 0;

  if (has_suffix (path, ".scope"))
    need_set_parent = false;

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, "cpu", path, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = crun_ensure_directory (cgroup_path, 0755, true, err);
  if (UNLIKELY (ret < 0))
    return ret;

  dirfd = open (cgroup_path, O_DIRECTORY | O_PATH | O_CLOEXEC);
  if (UNLIKELY (dirfd < 0))
    return crun_make_error (err, errno, "open `%s`", cgroup_path);

  if (resources->cpu->realtime_period)
    {
      len = sprintf (fmt_buf, "%" PRIu64, resources->cpu->realtime_period);

      if (need_set_parent)
        {
          ret = write_file_at_with_flags (dirfd, O_WRONLY | O_CLOEXEC, 0, "../cpu.rt_period_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = write_file_at_with_flags (dirfd, O_WRONLY | O_CLOEXEC, 0, "cpu.rt_period_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources->cpu->realtime_runtime)
    {
      len = sprintf (fmt_buf, "%" PRIu64, resources->cpu->realtime_runtime);

      if (need_set_parent)
        {
          ret = write_file_at_with_flags (dirfd, O_WRONLY | O_CLOEXEC, 0, "../cpu.rt_runtime_us", fmt_buf, len, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = write_file_at_with_flags (dirfd, O_WRONLY | O_CLOEXEC, 0, "cpu.rt_runtime_us", fmt_buf, len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
setup_missing_cpu_options_for_systemd (runtime_spec_schema_config_linux_resources *resources, bool cgroup2, const char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  int parent;
  int ret;

  if (resources == NULL || resources->cpu == NULL)
    return 0;

  if (! resources->cpu->burst_present)
    return 0;

  for (parent = 0; parent < 2; parent++)
    {
      cleanup_close int dirfd = -1;

      if (cgroup2)
        ret = append_paths (&cgroup_path, err, CGROUP_ROOT, path ? path : "", (parent ? ".." : NULL), NULL);
      else
        ret = append_paths (&cgroup_path, err, CGROUP_ROOT, "/cpu", path ? path : "", (parent ? ".." : NULL), NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd = open (cgroup_path, O_DIRECTORY | O_PATH | O_CLOEXEC);
      if (UNLIKELY (dirfd < 0))
        return crun_make_error (err, errno, "open `%s`", cgroup_path);

      ret = write_cpu_burst (dirfd, cgroup2, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
setup_cpuset_for_systemd_v1 (runtime_spec_schema_config_linux_resources *resources, const char *path, libcrun_error_t *err)
{
  cleanup_free char *cgroup_path = NULL;
  int parent;
  int ret;
  int levels;

  ret = append_paths (&cgroup_path, err, CGROUP_ROOT, "/cpuset", path ? path : "", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = crun_ensure_directory (cgroup_path, 0755, true, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = initialize_cpuset_subsystem_resources (cgroup_path, resources, err);
  if (UNLIKELY (ret < 0))
    return ret;

  // Check if we have a subcgroup defined. If not, we only need to write this on one level.
  levels = has_suffix (path, ".scope") ? 1 : 2;

  for (parent = 0; parent < levels; parent++)
    {
      cleanup_close int dirfd_cpuset = -1;
      cleanup_free char *path_to_cpuset = NULL;

      ret = append_paths (&path_to_cpuset, err, CGROUP_ROOT "/cpuset", path, (parent ? ".." : NULL), NULL);
      if (UNLIKELY (ret < 0))
        return ret;

      dirfd_cpuset = open (path_to_cpuset, O_DIRECTORY | O_PATH | O_CLOEXEC);
      if (UNLIKELY (dirfd_cpuset < 0))
        return crun_make_error (err, errno, "open `%s`", path_to_cpuset);

      ret = write_cpuset_resources (dirfd_cpuset, false, resources->cpu, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
systemd_finalize (struct libcrun_cgroup_args *args, char **path_out,
                  int cgroup_mode, const char *suffix, libcrun_error_t *err)
{
  runtime_spec_schema_config_linux_resources *resources = args->resources;
  cleanup_free char *cgroup_path = NULL;
  cleanup_free char *content = NULL;
  cleanup_free char *path = NULL;
  pid_t pid = args->pid;
  int ret;
  char *from, *to;
  char *saveptr = NULL;

  xasprintf (&cgroup_path, "/proc/%d/cgroup", pid);
  ret = read_all_file (cgroup_path, &content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  switch (cgroup_mode)
    {
    case CGROUP_MODE_HYBRID:
    case CGROUP_MODE_LEGACY:
      from = strstr (content, ":memory:");
      if (LIKELY (from != NULL))
        from += 8;
      else
        {
          from = strstr (content, ":pids:");
          if (UNLIKELY (from == NULL))
            return crun_make_error (err, 0, "cannot find memory or pids controller for the current process");

          from += 6;
        }

      to = strchr (from, '\n');
      if (UNLIKELY (to == NULL))
        return crun_make_error (err, 0, "cannot parse `%s`", PROC_SELF_CGROUP);
      *to = '\0';
      if (suffix == NULL)
        path = xstrdup (from);
      else
        {
          ret = append_paths (&path, err, from, suffix, NULL);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      *to = '\n';

      if (geteuid ())
        return 0;

      ret = setup_rt_runtime (resources, path, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = setup_cpuset_for_systemd_v1 (resources, path, err);
      if (UNLIKELY (ret < 0))
        return ret;

      for (from = strtok_r (content, "\n", &saveptr); from; from = strtok_r (NULL, "\n", &saveptr))
        {
          char *subpath, *subsystem;
          subsystem = strchr (from, ':') + 1;
          subpath = strchr (subsystem, ':') + 1;
          *(subpath - 1) = '\0';

          if (subsystem[0] == '\0')
            {
              if (cgroup_mode == CGROUP_MODE_LEGACY)
                continue;

              subsystem = "unified";
            }

          if (strcmp (subpath, path))
            {
              ret = enter_cgroup_subsystem (pid, subsystem, path, true, err);
              if (UNLIKELY (ret < 0))
                {
                  /* If it is a named hierarchy, skip the error.  */
                  if (strchr (subsystem, '='))
                    {
                      crun_error_release (err);
                      continue;
                    }
                  return ret;
                }
            }
        }

      break;

    case CGROUP_MODE_UNIFIED:
      {
        cleanup_free char *dir = NULL;

        from = strstr (content, "0::");
        if (UNLIKELY (from == NULL))
          return crun_make_error (err, 0, "cannot find cgroup2 for the current process");

        from += 3;
        to = strchr (from, '\n');
        if (UNLIKELY (to == NULL))
          return crun_make_error (err, 0, "cannot parse `%s`", PROC_SELF_CGROUP);
        *to = '\0';
        if (suffix == NULL)
          path = xstrdup (from);
        else
          {
            ret = append_paths (&path, err, from, suffix, NULL);
            if (UNLIKELY (ret < 0))
              return ret;
          }
        *to = '\n';

        ret = append_paths (&dir, err, CGROUP_ROOT, path, NULL);
        if (UNLIKELY (ret < 0))
          return ret;

        /* On cgroup v2, processes can be only in leaf nodes.  If a suffix is used,
           move the process immediately to the new location before enabling
           the controllers.  */
        ret = crun_ensure_directory (dir, 0755, true, err);
        if (UNLIKELY (ret < 0))
          return ret;

        ret = move_process_to_cgroup (pid, NULL, path, err);
        if (UNLIKELY (ret < 0))
          return ret;

        ret = enable_controllers (path, err);
        if (UNLIKELY (ret < 0))
          return ret;

        if (suffix)
          {
            ret = chown_cgroups (path, args->root_uid, args->root_gid, err);
            if (UNLIKELY (ret < 0))
              return ret;
          }
      }
      break;

    default:
      return crun_make_error (err, 0, "invalid cgroup mode `%d`", cgroup_mode);
    }

  ret = setup_missing_cpu_options_for_systemd (resources, cgroup_mode == CGROUP_MODE_UNIFIED, path, err);
  if (UNLIKELY (ret < 0))
    return ret;

  *path_out = path;
  path = NULL;

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
        {
          crun_make_error (&d->err, 0, "error `%s` systemd unit `%s`: got `%s`", d->op, unit, result);
          return -1;
        }
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

int
parse_sd_array (char *s, char **out, char **next, libcrun_error_t *err)
{
  char endchr;
  char *it, *dest;
  bool escaped = false;

  *out = NULL;
  *next = NULL;

  while (isspace (*s))
    s++;
  if (*s == '\0')
    return 0;
  else if (*s != '\'' && *s != '"')
    return crun_make_error (err, 0, "invalid string `%s`", s);

  it = s;
  endchr = *it++;
  *out = dest = it;

  while (1)
    {
      if (*it == '\0')
        return crun_make_error (err, 0, "invalid string `%s`", s);
      if (*it == endchr && ! escaped)
        {
          *it++ = '\0';
          while (isspace (*it))
            it++;
          if (*it == ',')
            {
              *next = ++it;
              *dest = '\0';
              return 0;
            }

          if (*it == ']' || *it == '\0')
            {
              *dest = '\0';
              return 0;
            }

          return crun_make_error (err, 0, "invalid character found `%c`", *it);
        }

      escaped = *it == '\\' ? ! escaped : false;
      if (! escaped)
        *dest++ = *it;
      it++;
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
  else if (*it == '[')
    {
      cleanup_free char *v_start = NULL;
      size_t n_parts = 0, parts_size = 32;
      cleanup_free char **parts = xmalloc (sizeof (char *) * parts_size);
      char *part;

      part = v_start = xstrdup (it + 1);
      while (1)
        {
          char *out = NULL, *next = NULL;
          int ret;

          ret = parse_sd_array (part, &out, &next, err);
          if (UNLIKELY (ret < 0))
            return ret;

          parts[n_parts++] = out;
          if (n_parts == parts_size - 1)
            {
              parts_size += 32;
              parts = xrealloc (parts, parts_size);
            }
          parts[n_parts] = NULL;
          if (next == NULL)
            break;

          part = next;
        }

      sd_err = sd_bus_message_open_container (m, 'r', "sv");
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus open container");

      sd_err = sd_bus_message_append (m, "s", name);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      sd_err = sd_bus_message_open_container (m, 'v', "as");
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus open container");

      sd_err = sd_bus_message_append_strv (m, parts);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", name);

      sd_err = sd_bus_message_close_container (m);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus close container");

      sd_err = sd_bus_message_close_container (m);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus close container");

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
  int rootless;
  int sd_err = 0;

  rootless = is_rootless (err);
  if (UNLIKELY (rootless < 0))
    return rootless;

  if (rootless)
    sd_err = sd_bus_default_user (bus);
  if (! rootless || sd_err < 0)
    sd_err = sd_bus_default_system (bus);
  if (sd_err < 0)
    return crun_make_error (err, -sd_err, "cannot open sd-bus");

  return 0;
}

static int
get_value_from_unified_map (runtime_spec_schema_config_linux_resources *resources, const char *name,
                            uint64_t *value, libcrun_error_t *err)
{
  char *endptr = NULL;
  size_t i;

  if (resources == NULL || resources->unified == NULL)
    return 0;

  for (i = 0; i < resources->unified->len; i++)
    if (strcmp (resources->unified->keys[i], name) == 0)
      {
        if (strcmp (resources->unified->values[i], "max") == 0)
          {
            *value = UINT64_MAX;
            return 1;
          }

        errno = 0;
        *value = (uint64_t) strtoll (resources->unified->values[i], &endptr, 10);
        if (UNLIKELY (errno))
          return crun_make_error (err, errno, "invalid value for `%s`: %s", name,
                                  resources->unified->values[i]);
        if (endptr && *endptr)
          return crun_make_error (err, 0, "invalid value for `%s`: %s", name,
                                  resources->unified->values[i]);
        return 1;
      }
  return 0;
}

static inline int
get_memory_low (runtime_spec_schema_config_linux_resources *resources, uint64_t *limit, libcrun_error_t *err)
{
  if (resources->memory && resources->memory->reservation_present)
    {
      *limit = resources->memory->reservation;
      return 1;
    }

  return get_value_from_unified_map (resources, "memory.low", limit, err);
}

static inline int
get_pids_max (runtime_spec_schema_config_linux_resources *resources, uint64_t *limit, libcrun_error_t *err)
{
  if (resources->pids && resources->pids->limit)
    {
      *limit = resources->pids->limit;
      return 1;
    }

  return get_value_from_unified_map (resources, "pids.max", limit, err);
}

static inline int
get_memory_max (runtime_spec_schema_config_linux_resources *resources, uint64_t *limit, libcrun_error_t *err)
{
  if (resources->memory && resources->memory->limit_present)
    {
      *limit = resources->memory->limit;
      return 1;
    }

  return get_value_from_unified_map (resources, "memory.max", limit, err);
}

static inline int
get_memory_swap_max (runtime_spec_schema_config_linux_resources *resources, uint64_t *limit, libcrun_error_t *err)
{
  if (resources->memory && resources->memory->swap_present)
    {
      *limit = resources->memory->swap;
      return 1;
    }

  return get_value_from_unified_map (resources, "memory.swap.max", limit, err);
}

static inline int
get_cpu_weight (runtime_spec_schema_config_linux_resources *resources, uint64_t *weight, libcrun_error_t *err)
{
  bool has_idle = false;
  uint64_t value;
  int ret;

  ret = get_value_from_unified_map (resources, "cpu.idle", &value, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret > 0 && value == 1)
    has_idle = true;

  if (resources->cpu && resources->cpu->shares_present)
    {
      if (has_idle)
        return crun_make_error (err, 0, "cannot set both `cpu.idle` and `cpu.shares`");

      /* Docker uses shares == 0 to specify no limit.  */
      if (resources->cpu->shares == 0)
        return 0;
      *weight = convert_shares_to_weight (resources->cpu->shares);
      return 1;
    }

  ret = get_value_from_unified_map (resources, "cpu.weight", weight, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret > 0)
    {
      if (has_idle)
        return crun_make_error (err, 0, "cannot set both `cpu.idle` and `cpu.weight`");

      return 1;
    }
  if (has_idle)
    {
      /* setting CPUWeight to 0 will tell systemd to set cpu.idle.  */
      *weight = 0;
      return 1;
    }
  return 0;
}

static int
read_uint64_value (const char *str, uint64_t *value, libcrun_error_t *err)
{
  char *endptr = NULL;

  errno = 0;
  *value = (uint64_t) strtoll (str, &endptr, 10);
  if (UNLIKELY (errno))
    return crun_make_error (err, errno, "invalid value: %s", str);
  if (endptr && *endptr)
    return crun_make_error (err, 0, "invalid value: %s", str);
  return 0;
}

/* Convert io.bfq.weight to io.weight doing the inverse conversion performed by systemd with BFQ_WEIGHT.  */
static inline uint64_t
IO_WEIGHT (uint64_t bfq_weight)
{
  return bfq_weight <= CGROUP_BFQ_WEIGHT_DEFAULT ? CGROUP_WEIGHT_DEFAULT - (CGROUP_BFQ_WEIGHT_DEFAULT - bfq_weight) * (CGROUP_WEIGHT_DEFAULT - CGROUP_WEIGHT_MIN) / (CGROUP_BFQ_WEIGHT_DEFAULT - CGROUP_BFQ_WEIGHT_MIN) : CGROUP_WEIGHT_DEFAULT + (bfq_weight - CGROUP_BFQ_WEIGHT_DEFAULT) * (CGROUP_WEIGHT_MAX - CGROUP_WEIGHT_DEFAULT) / (CGROUP_BFQ_WEIGHT_MAX - CGROUP_BFQ_WEIGHT_DEFAULT);
}

static int
append_io_weight (sd_bus_message *m, char **missing_properties, runtime_spec_schema_config_linux_resources *resources, libcrun_error_t *err)
{
  uint64_t weight;
  int sd_err;
  size_t i;
  int ret;

#  define APPEND_IO_WEIGHT(value)                                                      \
    do                                                                                 \
      {                                                                                \
        if (! property_missing_p (missing_properties, "IOWeight"))                     \
          {                                                                            \
            sd_err = sd_bus_message_append (m, "(sv)", "IOWeight", "t", weight);       \
            if (UNLIKELY (sd_err < 0))                                                 \
              return crun_make_error (err, -sd_err, "sd-bus message append IOWeight"); \
          }                                                                            \
    } while (0)

#  define APPEND_IO_DEVICE_WEIGHT(device, value)                                                      \
    do                                                                                                \
      {                                                                                               \
        if (! property_missing_p (missing_properties, "IODeviceWeight"))                              \
          {                                                                                           \
            sd_err = sd_bus_message_append (m, "(sv)", "IODeviceWeight", "a(st)", 1, device, weight); \
            if (UNLIKELY (sd_err < 0))                                                                \
              return crun_make_error (err, -sd_err, "sd-bus message append IODeviceWeight");          \
          }                                                                                           \
    } while (0)

  if (resources->block_io && resources->block_io->weight_present)
    {
      weight = IO_WEIGHT (resources->block_io->weight);
      APPEND_IO_WEIGHT (weight);
    }

  for (i = 0; resources->block_io && i < resources->block_io->weight_device_len; i++)
    {
      char name[64];

      snprintf (name, sizeof (name), "%" PRIu64 ":%" PRIu64,
                resources->block_io->weight_device[i]->major,
                resources->block_io->weight_device[i]->minor);
      weight = IO_WEIGHT (resources->block_io->weight_device[i]->weight);
      APPEND_IO_DEVICE_WEIGHT (name, weight);
    }

  for (i = 0; resources->unified && i < resources->unified->len; i++)
    {
      cleanup_free char *value = NULL;
      bool need_conversion = false;
      char *saveptr = NULL;
      char *line;

      if (strcmp (resources->unified->keys[i], "io.bfq.weight") == 0)
        {
          /* If io.bfq.weight was provided, it must be converted to io.weight.  */
          need_conversion = true;
        }
      else if (strcmp (resources->unified->keys[i], "io.weight") == 0)
        {
          /* If io.weight was provided, then it is expected to already be
             in the range [1, 10000] so IO_WEIGHT() is not needed.  */
          need_conversion = false;
        }
      else
        {
          /* Skip other keys.  */
          continue;
        }

      value = xstrdup (resources->unified->values[i]);

      for (line = strtok_r (value, "\n", &saveptr); line; line = strtok_r (NULL, "\n", &saveptr))
        {
          char *sep;

          sep = strchr (line, ' ');
          while (sep && *sep == ' ')
            *sep++ = '\0';

          ret = read_uint64_value (sep ? sep : line, &weight, err);
          if (UNLIKELY (ret < 0))
            return ret;
          if (need_conversion)
            weight = IO_WEIGHT (weight);

          if (sep == NULL || strcmp (line, "default") == 0)
            APPEND_IO_WEIGHT (weight);
          else
            APPEND_IO_DEVICE_WEIGHT (line, weight);
        }
    }

  return 0;
}

/* Adapted from systemd.  */
static int
bus_append_byte_array (sd_bus_message *m, const char *field, const void *buf, size_t n, libcrun_error_t *err)
{
  int ret;

  ret = sd_bus_message_open_container (m, SD_BUS_TYPE_STRUCT, "sv");
  if (ret < 0)
    return crun_make_error (err, -ret, "sd-bus open container");

  ret = sd_bus_message_append_basic (m, SD_BUS_TYPE_STRING, field);
  if (ret < 0)
    return crun_make_error (err, -ret, "sd_bus_message_append_basic");

  ret = sd_bus_message_open_container (m, 'v', "ay");
  if (ret < 0)
    return crun_make_error (err, -ret, "sd_bus_message_open_container");

  ret = sd_bus_message_append_array (m, 'y', buf, n);
  if (ret < 0)
    return crun_make_error (err, -ret, "sd_bus_message_append_array");

  ret = sd_bus_message_close_container (m);
  if (ret < 0)
    return crun_make_error (err, -ret, "sd_bus_message_close_container");

  ret = sd_bus_message_close_container (m);
  if (ret < 0)
    return crun_make_error (err, -ret, "sd_bus_message_close_container");

  return 1;
}

static int
append_uint64_from_unified_map (sd_bus_message *m,
                                char **missing_properties,
                                const char *attr,
                                const char *key,
                                runtime_spec_schema_config_linux_resources *resources,
                                libcrun_error_t *err)
{
  uint64_t value;
  int ret;

  if (property_missing_p (missing_properties, attr))
    return 0;

  ret = get_value_from_unified_map (resources, key, &value, err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret)
    {
      int sd_err = sd_bus_message_append (m, "(sv)", attr, "t", value);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append `%s`", attr);
    }

  return 0;
}

/* append a single "DeviceAllow" attribute to the message.  type can either be 'c' or 'b'.  */
static int
append_device_allow (sd_bus_message *m,
                     const char type,
                     int major,
                     int minor,
                     const char *access,
                     libcrun_error_t *err)
{
  char device[64];
  int sd_err;

  if (IS_WILDCARD (major) && ! IS_WILDCARD (minor))
    {
      libcrun_warning ("devices rule with wildcard for major is not supported and it is ignored with systemd");
      return 0;
    }

  if (IS_WILDCARD (major) && IS_WILDCARD (minor))
    snprintf (device, sizeof (device) - 1, "%s-*", type == 'c' ? "char" : "block");
  else if (IS_WILDCARD (minor))
    snprintf (device, sizeof (device) - 1, type == 'c' ? "char-%d" : "block-%d", major);
  else
    snprintf (device, sizeof (device) - 1, "/dev/%s/%d:%d", type == 'c' ? "char" : "block", major, minor);

  sd_err = sd_bus_message_append (m, "(sv)", "DeviceAllow", "a(ss)", 1, device, access);
  if (UNLIKELY (sd_err < 0))
    return crun_make_error (err, -sd_err, "sd-bus message append DeviceAllow `%s` with access `%s`", device, access);

  return 0;
}

#  define MODE_R 1
#  define MODE_W 2
#  define MODE_M 4

static int
access_to_mode (const char *access, libcrun_error_t *err)
{
  int mode = 0;

  while (access && *access)
    {
      int c = *access++;

      switch (c)
        {
        case 'r':
          mode |= MODE_R;
          break;

        case 'w':
          mode |= MODE_W;
          break;

        case 'm':
          mode |= MODE_M;
          break;

        default:
          return crun_make_error (err, 0, "unknown access string specified: `%c`", c);
        }
    }
  return mode;
}

/* check if the type b is included in type a.  */
static bool
has_same_type (const char *a, const char *b)
{
  bool a_all = a == NULL || strcmp (a, "a") == 0;
  if (b == NULL || strcmp (b, "a") == 0)
    return a_all;

  return a_all || strcmp (a, b) == 0;
}

/* check if there is already another "deny rule" specified before that already blocks the
 * device DEVICES[n].  */
static int
is_deny_rule_redundant (runtime_spec_schema_defs_linux_device_cgroup **devices, size_t n, libcrun_error_t *err)
{
  size_t i;
  int req_mode;

#  define CMP_DEV_NUM(a, b) ((a) == (b) || IS_WILDCARD (a) || IS_WILDCARD (b))

  req_mode = access_to_mode (devices[n]->access, err);
  if (UNLIKELY (req_mode < 0))
    return req_mode;

  for (i = n; i > 0; i--)
    {
      size_t current_rule = i - 1;
      int mode;

      if (! CMP_DEV_NUM (devices[n]->minor, devices[current_rule]->minor))
        continue;
      if (! CMP_DEV_NUM (devices[n]->major, devices[current_rule]->major))
        continue;

      if (! has_same_type (devices[n]->type, devices[current_rule]->type)
          && has_same_type ("a", devices[current_rule]->type))
        continue;

      mode = access_to_mode (devices[i]->access, err);
      if (UNLIKELY (mode < 0))
        return mode;

      if (devices[current_rule]->allow && (mode & req_mode))
        return 0;

      req_mode &= ! mode;

      /* no more access bits to validate.  */
      if (req_mode == 0)
        return 1;
    }

  return 0;
#  undef CMP_DEV_NUM
}

static size_t
find_first_rule_no_default (runtime_spec_schema_defs_linux_device_cgroup **devices, size_t n)
{
  size_t i;

  if (n == 0)
    return 1;

  /* Find the first rule that is after the last "block all".  */
  for (i = n - 1; i-- > 0;)
    {
      if ((is_empty_string (devices[i]->type) || strcmp (devices[i]->type, "a") == 0)
          && IS_WILDCARD (devices[i]->major)
          && IS_WILDCARD (devices[i]->minor)
          && (! devices[i]->allow))
        return i + 1;
    }

  /* If there is not a default rule, the skip to the first rule that is not a deny rule.  */
  for (i = 0; i < n; i++)
    if (devices[i]->allow)
      return i;

  /* All blocked.  Move at the end of the array and rely on the default block all devices rule.  */
  return n + 1;
}

static bool
has_allow_all (runtime_spec_schema_defs_linux_device_cgroup **devices, size_t n)
{
#  define DEV_TYPE_BLOCK 1
#  define DEV_TYPE_CHAR 2
  int remaining = DEV_TYPE_BLOCK | DEV_TYPE_CHAR;
  size_t i;

  for (i = 0; i < n; i++)
    {
      size_t current_rule = n - i - 1;
      if (! devices[current_rule]->allow)
        return false;

      if (IS_WILDCARD (devices[current_rule]->major) && IS_WILDCARD (devices[current_rule]->minor))
        {
          if (is_empty_string (devices[current_rule]->type) || strcmp (devices[current_rule]->type, "a") == 0)
            return true;

          if (strcmp (devices[current_rule]->type, "c") == 0)
            remaining &= ~DEV_TYPE_CHAR;
          else if (strcmp (devices[current_rule]->type, "b") == 0)
            remaining &= ~DEV_TYPE_BLOCK;

          if (remaining == 0)
            return true;
        }
    }
#  undef DEV_TYPE_BLOCK
#  undef DEV_TYPE_CHAR

  return false;
}

static int
append_devices (sd_bus_message *m,
                runtime_spec_schema_config_linux_resources *resources,
                libcrun_error_t *err)
{
  struct default_dev_s *default_devices = get_default_devices ();
  int ret, sd_err;
  size_t i;

  if (has_allow_all (resources->devices, resources->devices_len))
    {
      sd_err = sd_bus_message_append (m, "(sv)", "DevicePolicy", "s", "auto");
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append DevicePolicy");

      sd_err = sd_bus_message_append (m, "(sv)", "DeviceAllow", "a(ss)", 0);
      if (UNLIKELY (sd_err < 0))
        return crun_make_error (err, -sd_err, "sd-bus message append empty DeviceAllow");

      return 0;
    }

  sd_err = sd_bus_message_append (m, "(sv)", "DevicePolicy", "s", "strict");
  if (UNLIKELY (sd_err < 0))
    return crun_make_error (err, -sd_err, "sd-bus message append DevicePolicy");

  for (i = 0; default_devices[i].type; i++)
    {
      ret = append_device_allow (m, default_devices[i].type, default_devices[i].major, default_devices[i].minor, default_devices[i].access, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (resources == NULL)
    return 0;

  for (i = find_first_rule_no_default (resources->devices, resources->devices_len); i < resources->devices_len; i++)
    {
      runtime_spec_schema_defs_linux_device_cgroup *d = resources->devices[i];
      char type;

      if (! d->allow)
        {
          int redundant;

          redundant = is_deny_rule_redundant (resources->devices, i, err);
          if (UNLIKELY (redundant < 0))
            return redundant;

          if (redundant)
            continue;

          return crun_make_error (err, 0, "systemd does not support deny rules for devices");
        }

      if (d->type == NULL || strcmp (d->type, "a") == 0)
        type = 'a';
      else if (strcmp (d->type, "c") == 0)
        type = 'c';
      else if (strcmp (d->type, "b") == 0)
        type = 'b';
      else
        return crun_make_error (err, 0, "unknown device type `%s`", d->type);

      if (type != 'a')
        {
          ret = append_device_allow (m, type, d->major, d->minor, d->access, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      else
        {
          ret = append_device_allow (m, 'c', d->major, d->minor, d->access, err);
          if (UNLIKELY (ret < 0))
            return ret;
          ret = append_device_allow (m, 'b', d->major, d->minor, d->access, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }
    }

  return 0;
}

static int
append_resources (sd_bus_message *m,
                  bool is_update,
                  const char *state_dir,
                  runtime_spec_schema_config_linux_resources *resources,
                  int cgroup_mode,
                  libcrun_error_t *err)
{
  uint64_t value;
  int sd_err;
  int ret;
  cleanup_free char *dir = NULL;
  cleanup_free char **missing_properties = NULL;

  ret = append_paths (&dir, err, state_dir, SYSTEMD_MISSING_PROPERTIES_DIR, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  missing_properties = read_dir_entries (dir, err);
  if (UNLIKELY (missing_properties == NULL))
    {
      if (crun_error_get_errno (err) != ENOENT)
        return -1;

      /* The directory does not exist, so there are no missing features.  */
      crun_error_release (err);
    }

#  define APPEND_UINT64_VALUE(name, value)                                             \
    do                                                                                 \
      {                                                                                \
        if (! property_missing_p (missing_properties, name))                           \
          {                                                                            \
            sd_err = sd_bus_message_append (m, "(sv)", name, "t", value);              \
            if (UNLIKELY (sd_err < 0))                                                 \
              return crun_make_error (err, -sd_err, "sd-bus message append %s", name); \
          }                                                                            \
    } while (0)

#  define APPEND_UINT64(name, fn)              \
    do                                         \
      {                                        \
        ret = fn (resources, &value, err);     \
        if (UNLIKELY (ret < 0))                \
          return ret;                          \
        if (ret)                               \
          {                                    \
            APPEND_UINT64_VALUE (name, value); \
          }                                    \
    } while (0)

  if (resources == NULL)
    return 0;

  APPEND_UINT64 ("MemoryLow", get_memory_low);
  APPEND_UINT64 ("MemoryMax", get_memory_max);
  APPEND_UINT64 ("MemorySwapMax", get_memory_swap_max);
  APPEND_UINT64 ("TasksMax", get_pids_max);

  if (resources->cpu)
    {
      /* do not bother with systemd internal representation unless both values are specified */
      if (resources->cpu->quota && resources->cpu->period)
        {
          uint64_t quota = resources->cpu->quota;

          /* this conversion was copied from runc.  */
          quota = (quota * 1000000) / resources->cpu->period;
          if (quota % 10000)
            quota = ((quota / 10000) + 1) * 10000;

          APPEND_UINT64_VALUE ("CPUQuotaPerSecUSec", quota);
          APPEND_UINT64_VALUE ("CPUQuotaPeriodUSec", resources->cpu->period);
        }
    }

  switch (cgroup_mode)
    {
    case CGROUP_MODE_UNIFIED:
      {
        ret = append_io_weight (m, missing_properties, resources, err);
        if (UNLIKELY (ret < 0))
          return ret;

        APPEND_UINT64 ("CPUWeight", get_cpu_weight);

        ret = append_uint64_from_unified_map (m, missing_properties, "MemoryMin", "memory.min", resources, err);
        if (UNLIKELY (ret < 0))
          return ret;
        ret = append_uint64_from_unified_map (m, missing_properties, "MemoryHigh", "memory.high", resources, err);
        if (UNLIKELY (ret < 0))
          return ret;
        ret = append_uint64_from_unified_map (m, missing_properties, "MemoryZSwapMax", "memory.zswap.max", resources, err);
        if (UNLIKELY (ret < 0))
          return ret;

        if (resources->cpu && resources->cpu->cpus)
          {
            const char *property_name = "AllowedCPUs";
            cleanup_free char *allowed_cpus = NULL;
            size_t allowed_cpus_len = 0;

            ret = cpuset_string_to_bitmask (resources->cpu->cpus, &allowed_cpus, &allowed_cpus_len, err);
            if (UNLIKELY (ret < 0))
              return ret;

            if (! property_missing_p (missing_properties, property_name))
              {
                ret = bus_append_byte_array (m, property_name, allowed_cpus, allowed_cpus_len, err);
                if (UNLIKELY (ret < 0))
                  return ret;
              }
          }

        if (resources->cpu && resources->cpu->mems)
          {
            const char *property_name = "AllowedMemoryNodes";
            cleanup_free char *allowed_mems = NULL;
            size_t allowed_mems_len = 0;

            ret = cpuset_string_to_bitmask (resources->cpu->mems, &allowed_mems, &allowed_mems_len, err);
            if (UNLIKELY (ret < 0))
              return ret;

            if (! property_missing_p (missing_properties, property_name))
              {
                ret = bus_append_byte_array (m, property_name, allowed_mems, allowed_mems_len, err);
                if (UNLIKELY (ret < 0))
                  return ret;
              }
          }
      }
      break;

    case CGROUP_MODE_LEGACY:
    case CGROUP_MODE_HYBRID:
      if (resources->cpu && resources->cpu->shares > 0)
        APPEND_UINT64_VALUE ("CPUShares", resources->cpu->shares);
      break;

    default:
      return crun_make_error (err, 0, "invalid cgroup mode `%d`", cgroup_mode);
    }

#  undef APPEND_UINT64
#  undef APPEND_UINT64_VALUE

  if (! is_update || resources->devices)
    {
      ret = append_devices (m, resources, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  return 0;
}

static int
reset_failed_unit (sd_bus *bus, const char *unit)
{
  int sd_err;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  sd_bus_message *m = NULL, *reply = NULL;

  sd_err = sd_bus_message_new_method_call (bus, &m, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager", "ResetFailedUnit");
  if (UNLIKELY (sd_err < 0))
    goto exit;

  sd_err = sd_bus_message_append (m, "s", unit);
  if (UNLIKELY (sd_err < 0))
    goto exit;

  sd_err = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (sd_err < 0))
    goto exit;

  sd_err = 0;

exit:
  if (m)
    sd_bus_message_unref (m);
  if (reply)
    sd_bus_message_unref (reply);
  sd_bus_error_free (&error);

  return sd_err;
}

static int
enter_systemd_cgroup_scope (runtime_spec_schema_config_linux_resources *resources,
                            int cgroup_mode,
                            string_map *annotations,
                            const char *state_root,
                            const char *scope, const char *slice,
                            pid_t pid,
                            bool *can_retry,
                            libcrun_error_t *err)
{
  sd_bus *bus = NULL;
  sd_bus_message *m = NULL;
  sd_bus_message *reply = NULL;
  int sd_err, ret = 0;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  const char *object = NULL;
  struct systemd_job_removed_s job_data = {};
  int i;
  const char *boolean_opts[10];
  cleanup_free char *state_dir = NULL;

  *can_retry = false;

  ret = libcrun_get_state_directory (&state_dir, state_root, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

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

  sd_err = sd_bus_message_append (m, "(sv)", "DefaultDependencies", "b", 0);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append DefaultDependencies");
      goto exit;
    }

  if (annotations)
    {
      size_t prefix_len = sizeof (SYSTEMD_PROPERTY_PREFIX) - 1;
      size_t annotations_len = string_map_size (annotations);
      size_t i;

      for (i = 0; i < annotations_len; i++)
        {
          const char *key;
          const char *value;
          size_t len;

          ret = string_map_get_at (annotations, i, &key, &value);
          if (UNLIKELY (ret < 0))
            {
              ret = crun_make_error (err, 0, "internal error: failed to get annotation at index %zu", i);
              goto exit;
            }

          if (! has_prefix (key, SYSTEMD_PROPERTY_PREFIX))
            continue;

          len = strlen (key);
          if (len < prefix_len + 3)
            {
              ret = crun_make_error (err, EINVAL, "invalid systemd property name `%s`", key);
              goto exit;
            }

          ret = append_systemd_annotation (m, key + prefix_len, len - prefix_len,
                                           value, err);
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
          ret = crun_make_error (err, -sd_err, "sd-bus message append `%s`", boolean_opts[i]);
          goto exit;
        }
    }

  ret = append_resources (m, false, state_dir, resources, cgroup_mode, err);
  if (UNLIKELY (ret < 0))
    goto exit;

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
      if (reset_failed_unit (bus, scope) == 0)
        {
          sd_bus_error_free (&error);
          if (reply)
            sd_bus_message_unref (reply);

          error = SD_BUS_ERROR_NULL;
          reply = NULL;

          sd_err = sd_bus_call (bus, m, 0, &error, &reply);
        }
      if (sd_err < 0)
        {
          if (sd_err == -EROFS)
            {
              ret = register_missing_property_from_message (state_dir, error.message, err);
              if (UNLIKELY (ret < 0))
                goto exit;
              if (ret > 0)
                *can_retry = true;
            }
          ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call: %s", error.message ?: error.name);
          goto exit;
        }
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
libcrun_destroy_systemd_cgroup_scope (struct libcrun_cgroup_status *cgroup_status,
                                      libcrun_error_t *err)
{
  sd_bus *bus = NULL;
  sd_bus_message *m = NULL;
  sd_bus_message *reply = NULL;
  int ret = 0;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  const char *object;
  const char *scope = cgroup_status->scope;
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
      ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call: %s", error.message ?: error.name);
      goto exit;
    }

  ret = sd_bus_message_read (reply, "o", &object);
  if (UNLIKELY (ret < 0))
    {
      ret = crun_make_error (err, -ret, "sd-bus message read");
      goto exit;
    }

  ret = systemd_check_job_status (bus, &job_data, object, "removing", err);

  /* In case of a failed unit, call reset-failed so systemd can remove it. */
  reset_failed_unit (bus, scope);

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

static const char *
find_systemd_subgroup (string_map *annotations)
{
  const char *annotation;

  annotation = find_string_map_value (annotations, "run.oci.systemd.subgroup");
  if (annotation)
    {
      if (annotation[0] == '\0')
        return NULL;
      return annotation;
    }

  return NULL;
}

static int
libcrun_cgroup_enter_systemd (struct libcrun_cgroup_args *args,
                              struct libcrun_cgroup_status *out,
                              libcrun_error_t *err)
{
  runtime_spec_schema_config_linux_resources *resources = args->resources;
  const char *cgroup_path = args->cgroup_path;
  cleanup_free char *scope = NULL;
  cleanup_free char *path = NULL;
  cleanup_free char *slice = NULL;
  int retries_left = 32;
  const char *suffix;
  const char *id = args->id;
  pid_t pid = args->pid;
  int cgroup_mode;
  int ret;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  get_systemd_scope_and_slice (id, cgroup_path, &scope, &slice);

  for (;;)
    {
      bool can_retry = false;

      ret = enter_systemd_cgroup_scope (resources, cgroup_mode, args->annotations, args->state_root,
                                        scope, slice, pid, &can_retry, err);
      if (LIKELY (ret >= 0))
        break;

      if (can_retry && retries_left-- > 0)
        {
          crun_error_release (err);
          continue;
        }

      return ret;
    }

  suffix = find_systemd_subgroup (args->annotations);

  ret = systemd_finalize (args, &path, cgroup_mode, suffix, err);
  if (UNLIKELY (ret < 0))
    return ret;

  out->path = path;
  path = NULL;

  out->scope = scope;
  scope = NULL;
  return 0;
}

char *
get_cgroup_scope_path (const char *cgroup_path, const char *scope)
{
  char *path_to_scope = NULL;
  char *cur;

  path_to_scope = xstrdup (cgroup_path);

  cur = strchr (path_to_scope, '/');
  while (cur)
    {
      char *next = strchr (cur + 1, '/');
      if (next == NULL)
        break;

      *next = '\0';
      if (strcmp (cur, scope) == 0)
        return path_to_scope;
      *next = '/';

      cur = next;
      while (*cur == '/')
        cur++;
    }

  return path_to_scope;
}

static int
libcrun_destroy_cgroup_systemd (struct libcrun_cgroup_status *cgroup_status,
                                libcrun_error_t *err)
{
  cleanup_free char *path_to_scope = NULL;
  int mode;
  int ret;

  mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (mode < 0))
    return mode;

  ret = cgroup_killall_path (cgroup_status->path, SIGKILL, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  ret = libcrun_destroy_systemd_cgroup_scope (cgroup_status, err);
  if (UNLIKELY (ret < 0))
    crun_error_release (err);

  path_to_scope = get_cgroup_scope_path (cgroup_status->path, cgroup_status->scope);

  return destroy_cgroup_path (path_to_scope, mode, err);
}

static int
libcrun_update_resources_systemd (struct libcrun_cgroup_status *cgroup_status,
                                  const char *state_root,
                                  runtime_spec_schema_config_linux_resources *resources,
                                  libcrun_error_t *err)
{
  struct systemd_job_removed_s job_data = {};
  sd_bus_error error = SD_BUS_ERROR_NULL;
  cleanup_free char *state_dir = NULL;
  sd_bus_message *reply = NULL;
  sd_bus_message *m = NULL;
  sd_bus *bus = NULL;
  int sd_err, ret;
  int cgroup_mode;

  ret = libcrun_get_state_directory (&state_dir, state_root, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

  ret = open_sd_bus_connection (&bus, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = systemd_check_job_status_setup (bus, &job_data, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  sd_err = sd_bus_message_new_method_call (bus, &m, "org.freedesktop.systemd1",
                                           "/org/freedesktop/systemd1",
                                           "org.freedesktop.systemd1.Manager",
                                           "SetUnitProperties");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "set up dbus message");
      goto exit;
    }

  sd_err = sd_bus_message_append (m, "sb", cgroup_status->scope, 1);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus message append");
      goto exit;
    }

  sd_err = sd_bus_message_open_container (m, 'a', "(sv)");
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus open container");
      goto exit;
    }

  ret = append_resources (m, true, state_dir, resources, cgroup_mode, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  sd_err = sd_bus_message_close_container (m);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, -sd_err, "sd-bus close container");
      goto exit;
    }

  sd_err = sd_bus_call (bus, m, 0, &error, &reply);
  if (UNLIKELY (sd_err < 0))
    {
      ret = crun_make_error (err, sd_bus_error_get_errno (&error), "sd-bus call: %s", error.message ?: error.name);
      goto exit;
    }

  if (cgroup_mode != CGROUP_MODE_UNIFIED)
    {
      ret = setup_rt_runtime (resources, cgroup_status->path, err);
      if (UNLIKELY (ret < 0))
        goto exit;

      ret = setup_cpuset_for_systemd_v1 (resources, cgroup_status->path, err);
      if (UNLIKELY (ret < 0))
        goto exit;
    }

  ret = setup_missing_cpu_options_for_systemd (resources, cgroup_mode == CGROUP_MODE_UNIFIED, cgroup_status->path, err);
  if (UNLIKELY (ret < 0))
    goto exit;

  ret = 0;

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

#else
static int
libcrun_cgroup_enter_systemd (struct libcrun_cgroup_args *args,
                              struct libcrun_cgroup_status *out,
                              libcrun_error_t *err)
{
  (void) args;
  (void) out;

  return crun_make_error (err, ENOTSUP, "systemd not supported");
}

static int
libcrun_destroy_cgroup_systemd (struct libcrun_cgroup_status *cgroup_status,
                                libcrun_error_t *err)
{
  (void) cgroup_status;

  return crun_make_error (err, ENOTSUP, "systemd not supported");
}

static int
libcrun_update_resources_systemd (struct libcrun_cgroup_status *cgroup_status,
                                  const char *state_root,
                                  runtime_spec_schema_config_linux_resources *resources,
                                  libcrun_error_t *err)
{
  (void) cgroup_status;
  (void) state_root;
  (void) resources;

  return crun_make_error (err, ENOTSUP, "systemd not supported");
}
#endif

struct libcrun_cgroup_manager cgroup_manager_systemd = {
  .precreate_cgroup = NULL,
  .create_cgroup = libcrun_cgroup_enter_systemd,
  .destroy_cgroup = libcrun_destroy_cgroup_systemd,
  .update_resources = libcrun_update_resources_systemd,
};
