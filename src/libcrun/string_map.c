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
#include <stdlib.h>
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

#ifdef HAVE_HSEARCH_R
  struct hsearch_data htab;
  bool htab_initialized;
#endif

  bool sorted;
};

static int
compare_kv (const void *a, const void *b)
{
  return strcmp (((struct kv_s *) a)->key, ((struct kv_s *) b)->key);
}

const char *
find_string_map_value (string_map *map, const char *name)

{
  struct kv_s *r, key;

  if (map == NULL || map->len == 0)
    return NULL;

#ifdef HAVE_HSEARCH_R
  ENTRY e, *ep;

  /* Do not bother with hash tables for small maps.  */
  if (map->len < 8)
    goto fallback;

  if (! map->htab_initialized)
    {
      size_t i;

      if (hcreate_r (map->len, &map->htab) == 0)
        goto fallback;

      for (i = 0; i < map->len; i++)
        {
          e.key = (char *) map->kvs[i].key;
          e.data = map->kvs[i].value;
          if (hsearch_r (e, ENTER, &ep, &map->htab) == 0)
            {
              hdestroy_r (&map->htab);
              goto fallback;
            }
        }
      map->htab_initialized = true;
    }

  e.key = (char *) name;
  if (hsearch_r (e, FIND, &ep, &map->htab) == 0)
    return NULL;

  return ep->data;

fallback:
#endif

  if (! map->sorted)
    {
      qsort (map->kvs, map->len, sizeof (struct kv_s), compare_kv);
      map->sorted = true;
    }

  key.key = (char *) name;

  r = bsearch (&key, map->kvs, map->len, sizeof (struct kv_s), compare_kv);
  return r ? r->value : NULL;
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

  if (map->htab_initialized)
    hdestroy_r (&map->htab);

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
