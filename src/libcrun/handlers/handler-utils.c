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
#include <string.h>
#include <strings.h>
#include "../container.h"
#include "../utils.h"
#include "handler-utils.h"

int
has_case_suffix (const char *s, const char *suffix)
{
  const unsigned long s_len = strlen (s);
  const unsigned long suffix_len = strlen (suffix);
  if (s_len < suffix_len)
    return 0;

  return strcasecmp (s + s_len - suffix_len, suffix) == 0 ? 1 : 0;
}

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

      /* wasm-smart: annotation is a smart switch which only toggles wasm if it's necessary,
         following annotation is very useful for cases where users intend to run wasm workload on
         kubernetes cluster but workload also contains side-cars which could execute non-wasm workload.
         Example: Kubernetes clusters with service-mesh such as istio, linkerd etc
      */
      if (strcmp (annotation, "wasm-smart") == 0)
        {
          return ((has_case_suffix (entrypoint_executable, ".wat") > 0) || (has_case_suffix (entrypoint_executable, ".wasm") > 0)) ? 1 : 0;
        }
      return strcmp (annotation, "wasm") == 0 ? 1 : 0;
    }

  annotation = find_annotation (container, "module.wasm.image/variant");
  if (annotation)
    {

      /* compat-smart: annotation is a smart switch which only toggles wasm if it's necessary,
         following annotation is very useful for cases where users intend to run wasm workload on
         kubernetes cluster but workload also contains side-cars which could execute non-wasm workload.
         Example: Kubernetes clusters with service-mesh such as istio, linkerd etc
      */
      if (strcmp (annotation, "compat-smart") == 0)
        {
          return ((has_case_suffix (entrypoint_executable, ".wat") > 0) || (has_case_suffix (entrypoint_executable, ".wasm") > 0)) ? 1 : 0;
        }

      return strcmp (annotation, "compat") == 0 ? 1 : 0;
    }

  return 0;
}

wasm_encoding_t
wasm_interpret_header (const char *header, const size_t len)
{
  if (len < 8)
    return WASM_ENC_INVALID;

  // Check for the WebAssembly magic bytes
  // See: https://webassembly.github.io/spec/core/binary/modules.html#binary-module
  if (memcmp (header, "\0asm", 4))
    return WASM_ENC_INVALID;

  /* The next four bytes are the WebAssembly version.
     We don't care for the specific WebAssembly version
     so we only read the value of the `layer` field which
     was defined by the component spec.
     See: https://github.com/WebAssembly/component-model/blob/main/design/mvp/Binary.md#component-definitions
  */
  if (header[6] == '\0' && header[7] == '\0')
    return WASM_ENC_MODULE;

  // `layer` does not equal `0x00 0x00` so we are working
  // with a component.
  return WASM_ENC_COMPONENT;
}
