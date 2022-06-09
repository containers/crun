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
  const char *name;
  const char *feature_string;

  int (*load) (void **cookie, libcrun_error_t *err);
  int (*unload) (void *cookie, libcrun_error_t *err);

  int (*exec_func) (void *cookie, libcrun_container_t *container,
                    const char *pathname, char *const argv[]);

  int (*configure_container) (void *cookie, enum handler_configure_phase phase,
                              libcrun_context_t *context, libcrun_container_t *container,
                              const char *rootfs, libcrun_error_t *err);

  int (*can_handle_container) (libcrun_container_t *container, libcrun_error_t *err);
};

struct custom_handler_manager_s;

LIBCRUN_PUBLIC struct custom_handler_manager_s *libcrun_handler_manager_create (libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_handler_manager_load_directory (struct custom_handler_manager_s *manager, const char *path, libcrun_error_t *err);
LIBCRUN_PUBLIC void handler_manager_free (struct custom_handler_manager_s *manager);

LIBCRUN_PUBLIC struct custom_handler_s *handler_by_name (struct custom_handler_manager_s *manager, const char *name);
LIBCRUN_PUBLIC void libcrun_handler_manager_print_feature_tags (struct custom_handler_manager_s *manager, FILE *out);

LIBCRUN_PUBLIC int libcrun_configure_handler (struct custom_handler_manager_s *manager,
                                              libcrun_context_t *context,
                                              libcrun_container_t *container,
                                              struct custom_handler_s **out,
                                              void **cookie, libcrun_error_t *err);

typedef struct custom_handler_s *(*run_oci_get_handler_cb) ();

#endif
