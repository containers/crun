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
#include "utils.h"
#include <stdio.h>

struct custom_handler_s
{
  const char *name;
  const char *feature_string;

  const char *alias;

  int (*load) (void **cookie, libcrun_error_t *err);
  int (*unload) (void *cookie, libcrun_error_t *err);

  int (*run_func) (void *cookie, libcrun_container_t *container,
                   const char *pathname, char *const argv[]);

  int (*exec_func) (void *cookie, libcrun_container_t *container,
                    const char *pathname, char *const argv[]);

  int (*configure_container) (void *cookie, enum handler_configure_phase phase,
                              libcrun_context_t *context, libcrun_container_t *container,
                              const char *rootfs, libcrun_error_t *err);

  int (*can_handle_container) (libcrun_container_t *container, libcrun_error_t *err);

  int (*modify_oci_configuration) (void *cookie, libcrun_context_t *context,
                                   runtime_spec_schema_config_schema *def,
                                   libcrun_error_t *err);
};

struct custom_handler_manager_s;

LIBCRUN_PUBLIC struct custom_handler_manager_s *libcrun_handler_manager_create (libcrun_error_t *err);
LIBCRUN_PUBLIC int libcrun_handler_manager_load_directory (struct custom_handler_manager_s *manager, const char *path, libcrun_error_t *err);
LIBCRUN_PUBLIC void handler_manager_free (struct custom_handler_manager_s *manager);

LIBCRUN_PUBLIC struct custom_handler_s *handler_by_name (struct custom_handler_manager_s *manager, const char *name);
LIBCRUN_PUBLIC void libcrun_handler_manager_print_feature_tags (struct custom_handler_manager_s *manager, FILE *out);

struct custom_handler_instance_s
{
  struct custom_handler_s *vtable;
  void *cookie;
};

LIBCRUN_PUBLIC int libcrun_configure_handler (struct custom_handler_manager_s *manager,
                                              libcrun_context_t *context,
                                              libcrun_container_t *container,
                                              struct custom_handler_instance_s **out,
                                              libcrun_error_t *err);

typedef struct custom_handler_s *(*run_oci_get_handler_cb) ();

#define cleanup_custom_handler_instance __attribute__ ((cleanup (cleanup_custom_handler_instancep)))

static inline void
cleanup_custom_handler_instancep (struct custom_handler_instance_s **p)
{
  struct custom_handler_instance_s *handler = (struct custom_handler_instance_s *) *p;
  if (handler)
    {
      if (handler->vtable)
        {
          libcrun_error_t tmp_err = NULL;
          int tmp_ret;

          tmp_ret = handler->vtable->unload (handler->cookie, &tmp_err);
          if (UNLIKELY (tmp_ret < 0))
            crun_error_release (&tmp_err);
        }
      free (handler);
    }
}

#endif
