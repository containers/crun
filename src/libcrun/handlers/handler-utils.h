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
#ifndef HANDLER_UTILS_H
#define HANDLER_UTILS_H

#include "../container.h"
#include <unistd.h>

typedef enum
{
  WASM_ENC_INVALID,
  WASM_ENC_MODULE,
  WASM_ENC_COMPONENT
} wasm_encoding_t;

int has_case_suffix (const char *s, const char *suffix);

int wasm_can_handle_container (libcrun_container_t *container, libcrun_error_t *err);

wasm_encoding_t wasm_interpret_header (const char *header, const size_t len);

#endif
