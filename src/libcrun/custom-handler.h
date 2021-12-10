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

#ifndef CUSTOM_HANDLER_H
#define CUSTOM_HANDLER_H

#include "container.h"
#include <stdio.h>

struct custom_handler_s
{
  int (*exec_func) (void *container, void *arg, const char *pathname, char *const argv[]);
  void *exec_func_arg;

  int (*post_configure_mounts) (libcrun_context_t *context, libcrun_container_t *container, const char *rootfs, libcrun_error_t *err);
};

int libcrun_configure_handler (libcrun_context_t *context, libcrun_container_t *container, struct custom_handler_s *out, libcrun_error_t *err);

void print_handlers_feature_tags (FILE *out);

#endif
