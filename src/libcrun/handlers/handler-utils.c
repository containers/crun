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

      /* wasm: annotation forces wasm, not allowing for the execution of non-wasm workloads.
         disable: disables wasm, not allowing the execution of wasm workloads.
      */

      if (strcmp (annotation, "wasm") == 0)
        return 1;
      
      if (strcmp (annotation, "disable") == 0)
        return 0;
    }

  annotation = find_annotation (container, "module.wasm.image/variant");
  if (annotation)
    {

      /* compat: annotation forces wasm, not allowing for the execution of non-wasm workloads.
         disable: disables wasm, not allowing the execution of wasm workloads.
      */

      if (strcmp (annotation, "compat") == 0)
        return 1;
      
      if (strcmp (annotation, "disable") == 0)
        return 0;
    }

  /* The default behaviour (previously enabled by the compat-smart/wasm-smart annotation)
     is a smart switch which only toggles wasm if it's necessary, it's very useful for 
     cases where users intend to run wasm workload on kubernetes cluster but workload 
     also contains side-cars which could execute non-wasm workload.
     Example: Kubernetes clusters with service-mesh such as istio, linkerd etc
  */

  return ((has_suffix (entrypoint_executable, ".wat") > 0) || (has_suffix (entrypoint_executable, ".wasm") > 0)) ? 1 : 0;
}