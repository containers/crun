/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2026 Eugene Gvozdetsky <gvozdet@gmail.com>
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
#ifndef IO_URING_H
#define IO_URING_H

#include <config.h>
#include "error.h"
#include "container.h"

int libcrun_check_io_uring_restrictions (libcrun_container_t *container, libcrun_error_t *err);

int libcrun_apply_io_uring_restrictions (libcrun_container_t *container, libcrun_error_t *err);

#endif
