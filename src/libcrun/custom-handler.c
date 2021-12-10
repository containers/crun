/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2020, 2021 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include "custom-handler.h"
#include "container.h"
#include "utils.h"
#include "linux.h"
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sched.h>

#ifdef HAVE_DLOPEN
#  include <dlfcn.h>
#endif

#if HAVE_DLOPEN && HAVE_LIBKRUN
extern struct custom_handler_s handler_libkrun;
#endif
#if HAVE_DLOPEN && HAVE_WASMEDGE
extern struct custom_handler_s handler_wasmedge;
#endif
#if HAVE_DLOPEN && HAVE_WASMER
extern struct custom_handler_s handler_wasmer;
#endif

static struct custom_handler_s *static_handlers[] = {
#if HAVE_DLOPEN && HAVE_LIBKRUN
  &handler_libkrun,
#endif
#if HAVE_DLOPEN && HAVE_WASMEDGE
  &handler_wasmedge,
#endif
#if HAVE_DLOPEN && HAVE_WASMER
  &handler_wasmer,
#endif
  NULL,
};

struct custom_handler_manager_s
{
  struct custom_handler_s **handlers;
};

struct custom_handler_manager_s *
handler_manager_create (libcrun_error_t *err arg_unused)
{
  struct custom_handler_manager_s *m;

  m = xmalloc0 (sizeof (struct custom_handler_manager_s));
  m->handlers = static_handlers;
  return m;
}

void
handler_manager_free (struct custom_handler_manager_s *manager)
{
  free (manager);
}

struct custom_handler_s *
handler_by_name (struct custom_handler_manager_s *manager, const char *name)
{
  size_t i;

  for (i = 0; manager->handlers[i]; i++)
    if (strcmp (manager->handlers[i]->name, name) == 0)
      return manager->handlers[i];
  return NULL;
}

void
handler_manager_print_feature_tags (struct custom_handler_manager_s *manager, FILE *out)
{
  size_t i;

  for (i = 0; manager->handlers[i]; i++)
    fprintf (out, "+%s ", manager->handlers[i]->feature_string);
}

static int
find_handler_for_container (struct custom_handler_manager_s *manager,
                            libcrun_container_t *container,
                            struct custom_handler_s **out,
                            void **cookie,
                            libcrun_error_t *err)
{
  size_t i;

  *out = NULL;
  *cookie = NULL;

  for (i = 0; manager->handlers[i]; i++)
    {
      int ret;

      if (manager->handlers[i]->can_handle_container == NULL)
        continue;

      ret = manager->handlers[i]->can_handle_container (container, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (ret)
        {
          *out = manager->handlers[i];
          return (*out)->load (cookie, err);
        }
    }

  return 0;
}

int
libcrun_configure_handler (struct custom_handler_manager_s *manager,
                           libcrun_context_t *context,
                           libcrun_container_t *container,
                           struct custom_handler_s **out,
                           void **cookie,
                           libcrun_error_t *err)
{
  const char *explicit_handler;
  const char *annotation;

  *out = NULL;
  *cookie = NULL;

  annotation = find_annotation (container, "run.oci.handler");

  /* Fail with EACCESS if global handler is already configured and there was a attempt to override it via spec.  */
  if (context->handler != NULL && annotation != NULL)
    return crun_make_error (err, EACCES, "invalid attempt to override already configured global handler: `%s`", context->handler);

  explicit_handler = context->handler ? context->handler : annotation;

  /* If an explicit handler was requested, use it.  */
  if (explicit_handler)
    {
      if (manager == NULL)
        return crun_make_error (err, 0, "handler requested but no manager configured: `%s`", context->handler);

      *out = handler_by_name (manager, explicit_handler);
      if (*out == NULL)
        return crun_make_error (err, 0, "invalid handler specified `%s`", explicit_handler);

      return (*out)->load (cookie, err);
    }

  if (manager == NULL)
    return 0;

  return find_handler_for_container (manager, container, out, cookie, err);
}
