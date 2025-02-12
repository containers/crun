/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2025 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include <errno.h>
#include "string_map.h"
#include "utils.h"

#include <ocispec/runtime_spec_schema_config_schema.h>

struct kv_s
{
  char *key;
  char *value;
};

struct string_map_s
{
  size_t len;
  struct kv_s *kvs;
};

const char *
find_string_map_value (string_map *map, const char *name)

{
  size_t i;

  if (map == NULL)
    return NULL;

  for (i = 0; i < map->len; i++)
    {
      if (strcmp (map->kvs[i].key, name) == 0)
        return map->kvs[i].value;
    }
  return NULL;
}

string_map *
make_string_map_from_json (json_map_string_string *jmap)
{
  struct string_map_s *new_map = xmalloc0 (sizeof (struct string_map_s));
  size_t i;

  if (jmap == NULL)
    return new_map;

  new_map->len = jmap->len;
  new_map->kvs = xmalloc0 (sizeof (struct kv_s) * (jmap->len + 1));

  for (i = 0; i < jmap->len; i++)
    {
      new_map->kvs[i].key = xstrdup (jmap->keys[i]);
      new_map->kvs[i].value = xstrdup (jmap->values[i]);
    }

  return new_map;
}

int
string_map_get_at (string_map *map, size_t index, const char **name, const char **value)
{
  if (map == NULL || index >= map->len)
    {
      errno = ERANGE;
      return -1;
    }

  *name = map->kvs[index].key;
  *value = map->kvs[index].value;

  return 0;
}

void
free_string_map (string_map *map)
{
  size_t i;

  for (i = 0; i < map->len; i++)
    {
      free (map->kvs[i].key);
      free (map->kvs[i].value);
    }
  free (map->kvs);
  free (map);
}

size_t
string_map_size (string_map *map)
{
  return map->len;
}
