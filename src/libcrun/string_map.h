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

#ifndef STRING_MAP_H
#define STRING_MAP_H

#define _GNU_SOURCE

#include <config.h>
#include <ocispec/runtime_spec_schema_config_schema.h>
#include "error.h"

struct string_map_s;
typedef struct string_map_s string_map;

const char *find_string_map_value (string_map *map, const char *name);

string_map *make_string_map_from_json (json_map_string_string *jmap);

void free_string_map (string_map *map);

int string_map_get_at (string_map *map, size_t index, const char **name, const char **value);

size_t string_map_size (string_map *map);

#endif
