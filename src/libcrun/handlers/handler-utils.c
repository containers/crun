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

#define _GNU_SOURCE

#include <config.h>
#include "../container.h"
#include "../utils.h"
#include "handler-utils.h"

int
wasm_can_handle_container (libcrun_container_t *container, libcrun_error_t *err arg_unused)
{
  const char *annotation;
  const char *entrypoint_executable;

  if (container->container_def->process == NULL || container->container_def->process->args == NULL)
    return 0;

  entrypoint_executable = container->container_def->process->args[0];

  annotation = find_annotation (container, "run.oci.handler");
  if (annotation)
    {

      /* wasm-smart: annotation is a smart switch which only toggles wasm if its necessary,
         following annotation is very useful for cases where users intends to run wasm workload on
         kubernetes cluster but workload also contains side-cars which could execute non-wasm workload.
         Example: Kubernetes clusters with service-mesh such as istio, linkerd etc
      */
      if (strcmp (annotation, "wasm-smart") == 0)
        {
          return ((has_suffix (entrypoint_executable, ".wat") > 0) || (has_suffix (entrypoint_executable, ".wasm") > 0)) ? 1 : 0;
        }
      return strcmp (annotation, "wasm") == 0 ? 1 : 0;
    }

  annotation = find_annotation (container, "module.wasm.image/variant");
  if (annotation)
    {

      /* compat-smart: annotation is a smart switch which only toggles wasm if its necessary,
         following annotation is very useful for cases where users intends to run wasm workload on
         kubernetes cluster but workload also contains side-cars which could execute non-wasm workload.
         Example: Kubernetes clusters with service-mesh such as istio, linkerd etc
      */
      if (strcmp (annotation, "compat-smart") == 0)
        {
          return ((has_suffix (entrypoint_executable, ".wat") > 0) || (has_suffix (entrypoint_executable, ".wasm") > 0)) ? 1 : 0;
        }

      return strcmp (annotation, "compat") == 0 ? 1 : 0;
    }

  return 0;
}
