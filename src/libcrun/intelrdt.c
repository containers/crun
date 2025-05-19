/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2023 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include "linux.h"
#include "utils.h"
#include "intelrdt.h"
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <errno.h>

#define INTEL_RDT_MOUNT_POINT "/sys/fs/resctrl"
#define SCHEMATA_FILE "schemata"
#define TASKS_FILE "tasks"
#define RDTGROUP_SUPER_MAGIC 0x7655821

static int
is_rdt_mounted (libcrun_error_t *err)
{
  struct statfs sfs;
  int ret;

  ret = statfs (INTEL_RDT_MOUNT_POINT, &sfs);
  if (ret < 0)
    return crun_make_error (err, errno, "statfs `%s`", INTEL_RDT_MOUNT_POINT);

  return sfs.f_type == RDTGROUP_SUPER_MAGIC;
}

int
get_rdt_value (char **out, const char *l3_cache_schema, const char *mem_bw_schema, char *const *schemata)
{
  cleanup_free char *schemata_joined = NULL;
  size_t schemata_size = 0;

  while (schemata && schemata[schemata_size])
    schemata_size++;

  if (schemata_size > 0)
    schemata_joined = str_join_array (0, schemata_size, schemata, "\n");

  return xasprintf (out, "%s%s%s%s%s\n", l3_cache_schema ?: "",
                    (l3_cache_schema && mem_bw_schema) ? "\n" : "", mem_bw_schema ?: "",
                    ((l3_cache_schema || mem_bw_schema) && schemata_joined) ? "\n" : "", schemata_joined ?: "");
}

struct key_value
{
  int key;
  int value;
};

static int
kv_cmp (const void *p1, const void *p2)
{
  const struct key_value *kv1 = p1;
  const struct key_value *kv2 = p2;

  return kv1->key - kv2->key;
}

static int
count_parts (const char *str)
{
  const char *it;
  int ret = 0;

  for (it = str; *it; it++)
    {
      if (*it == ';' || *(it + 1) == '\0')
        ret++;
    }
  return ret;
}

static int
read_kv (const char *value, struct key_value *out)
{
  char *endptr;

  out->key = strtoll (value, &endptr, 10);
  if (*endptr != '=')
    return 1;

  endptr++;
  out->value = strtoll (endptr, NULL, 16);
  return 0;
}

int
compare_rdt_configurations (const char *a, const char *b)
{
  cleanup_free struct key_value *kv = NULL;
  size_t i, n_parts_a = 0, n_parts_b = 0;
  cleanup_free char *a_copy = NULL;
  cleanup_free char *b_copy = NULL;
  const char *it;
  char *end;
  int ret;

  it = strchr (a, ':');
  a = it ? it + 1 : a;

  it = strchr (b, ':');
  b = it ? it + 1 : b;

  n_parts_a = count_parts (a);
  n_parts_b = count_parts (b);

  if (n_parts_a != n_parts_b)
    return 1;

  kv = xmalloc (sizeof (struct key_value) * (n_parts_a + 1));

  end = a_copy = xstrdup (a);
  i = 0;
  while ((it = strsep (&end, ";")))
    {
      if (it[0] == '\0')
        break;
      ret = read_kv (it, &(kv[i]));
      if (ret)
        return 1;
      i++;
    }

  qsort (kv, i, sizeof (struct key_value), kv_cmp);

  end = b_copy = xstrdup (b);
  while ((it = strsep (&end, ";")))
    {
      struct key_value key;
      struct key_value *res;

      if (it[0] == '\0')
        break;

      ret = read_kv (it, &key);
      if (ret)
        return 1;

      res = bsearch (&key, kv, n_parts_a, sizeof (struct key_value), kv_cmp);
      if (res == NULL || res->value != key.value)
        return 1;
    }

  return 0;
}

static int
validate_rdt_configuration (const char *name, const char *l3_cache_schema, const char *mem_bw_schema, libcrun_error_t *err)
{
  cleanup_free char *existing_content = NULL;
  cleanup_free char *path = NULL;
  char *it, *end;
  int ret;

  ret = append_paths (&path, err, INTEL_RDT_MOUNT_POINT, name, SCHEMATA_FILE, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = read_all_file (path, &existing_content, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  end = existing_content;
  while ((it = strsep (&end, "\n")))
    {
      ret = 0;

      if (mem_bw_schema && has_prefix (it, "MB:"))
        ret = compare_rdt_configurations (it, mem_bw_schema);

      if (l3_cache_schema && has_prefix (it, "L3:"))
        ret = compare_rdt_configurations (it, l3_cache_schema);

      if (ret)
        return crun_make_error (err, 0, "the resctl group `%s` has a different configuration", name);
    }

  return 0;
}

static int
write_intelrdt_string (int fd, const char *file, const char *l3_cache_schema, const char *mem_bw_schema, char *const *schemata, libcrun_error_t *err)
{
  cleanup_free char *formatted = NULL;
  int len, ret;

  len = get_rdt_value (&formatted, l3_cache_schema, mem_bw_schema, schemata);
  if (len < 0)
    return crun_make_error (err, errno, "internal error get_rdt_value");

  ret = write (fd, formatted, len);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "write `%s`", file);

  return 0;
}

/* filter any line in the l3_cache_schema that starts with MB:.  */
char *
intelrdt_clean_l3_cache_schema (const char *l3_cache_schema)
{
  size_t i, j, len = strlen (l3_cache_schema);
  char *ret;

  ret = xmalloc (len + 1);

  for (i = 0, j = 0; i < len; i++)
    {
      if (l3_cache_schema[i] == 'M' && l3_cache_schema[i + 1] == 'B' && l3_cache_schema[i + 2] == ':')
        {
          i += 3;
          while (l3_cache_schema[i] != '\n' && l3_cache_schema[i] != '\0')
            i++;
          continue;
        }
      ret[j++] = l3_cache_schema[i];
    }
  ret[j] = '\0';
  return ret;
}

int
resctl_create (const char *name, bool explicit_clos_id, bool *created, const char *l3_cache_schema, const char *mem_bw_schema, libcrun_error_t *err)
{
  cleanup_free char *cleaned_l3_cache_schema = NULL;
  cleanup_free char *path = NULL;
  int exist;
  int ret;

  *created = false;

  ret = is_rdt_mounted (err);
  if (UNLIKELY (ret < 0))
    return ret;
  if (ret == 0)
    return crun_make_error (err, 0, "the resctl file system is not mounted");

  ret = append_paths (&path, err, INTEL_RDT_MOUNT_POINT, name, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  exist = crun_path_exists (path, err);
  if (UNLIKELY (exist < 0))
    return exist;

  if (l3_cache_schema && strstr (l3_cache_schema, "MB:"))
    l3_cache_schema = cleaned_l3_cache_schema = intelrdt_clean_l3_cache_schema (l3_cache_schema);

  /* If the closID was specified and both l3cache and bwSchema are unset, the group
     must exist.  */
  if (explicit_clos_id && l3_cache_schema == NULL && mem_bw_schema == NULL)
    {
      if (exist)
        return 0;

      return crun_make_error (err, 0, "the resctl group `%s` does not exist", name);
    }

  /* If the closID exists then it must match the specified configuration.  */
  if (exist && (l3_cache_schema != NULL || mem_bw_schema != NULL))
    return validate_rdt_configuration (name, l3_cache_schema, mem_bw_schema, err);

  /* At this point, assume it was created.  */
  ret = crun_ensure_directory (path, 0755, true, err);
  if (UNLIKELY (ret < 0))
    return ret;
  *created = true;

  return 0;
}

int
resctl_move_task_to (const char *name, pid_t pid, libcrun_error_t *err)
{
  cleanup_free char *path = NULL;
  char pid_str[32];
  int len;
  int ret;

  ret = append_paths (&path, err, INTEL_RDT_MOUNT_POINT, name, TASKS_FILE, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  len = sprintf (pid_str, "%d", pid);

  return write_file (path, pid_str, len, err);
}

int
resctl_update (const char *name, const char *l3_cache_schema, const char *mem_bw_schema,
               char *const *schemata, libcrun_error_t *err)
{
  const char *actual_l3_cache_schema = l3_cache_schema;
  cleanup_free char *cleaned_l3_cache_schema = NULL;
  cleanup_free char *path = NULL;
  cleanup_close int fd = -1;
  int ret;

  /* Nothing to do.  */
  if (l3_cache_schema == NULL && mem_bw_schema == NULL && schemata == NULL)
    return 0;

  ret = append_paths (&path, err, INTEL_RDT_MOUNT_POINT, name, SCHEMATA_FILE, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  if (l3_cache_schema && strstr (l3_cache_schema, "MB:"))
    {
      cleaned_l3_cache_schema = intelrdt_clean_l3_cache_schema (l3_cache_schema);
      actual_l3_cache_schema = cleaned_l3_cache_schema;
    }

  fd = open (path, O_WRONLY | O_CLOEXEC);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open `%s` for writing", path);

  return write_intelrdt_string (fd, path, actual_l3_cache_schema, mem_bw_schema, schemata, err);
}

int
resctl_destroy (const char *name, libcrun_error_t *err)
{
  cleanup_free char *path = NULL;
  int ret;

  ret = append_paths (&path, err, INTEL_RDT_MOUNT_POINT, name, NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = rmdir (path);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "rmdir `%s`", path);

  return 0;
}
