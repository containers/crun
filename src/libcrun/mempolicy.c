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

#include <config.h>
#include "linux.h"
#include "utils.h"
#include <ocispec/runtime_spec_schema_config_schema.h>

#ifdef HAVE_NUMA
#  include <numa.h>
#  include <numaif.h>
#  include "mempolicy_internal.h"

#  define CRUN_NUMA_API_VERSION 2 /* numa.h LIBNUMA_API_VERSION at the time of writing */
#  define CRUN_NUMA_MPOL_MAX 7    /* numaif.h MPOL_MAX at the time of writing */

#  ifndef LIBNUMA_API_VERSION
#    error "Unable to determine libnuma api version"
#  else
#    if LIBNUMA_API_VERSION > CRUN_NUMA_API_VERSION
#      warning "This code was written with libnuma API version 2. numa.h reports a higher version"
#    endif
#  endif
#  ifndef MPOL_MAX
#    error "Unable to determine numaif interface version"
#  else
#    if MPOL_MAX > CRUN_NUMA_MPOL_MAX
#      warning "This code was written with numaif MPOL_MAX 7. numaif.h reports a higher version"
#    endif
#  endif

static int
mpol_str2int (const char *str, const str2int_map_t *map)
{
  int idx = 0;

  while (map[idx].name != NULL)
    {
      if (! strcmp (map[idx].name, str))
        {
          return map[idx].value;
        }
      idx++;
    }

  errno = EINVAL;
  return -1;
}
#endif

int
libcrun_set_mempolicy (runtime_spec_schema_config_schema *def, libcrun_error_t *err)
{
#ifdef HAVE_NUMA
  runtime_spec_schema_config_linux_memory_policy *memory_policy = NULL;
  int mpol_mode = 0;
  int mpol_flag = 0;
  int mpol_mode_flags = 0;
  struct bitmask *nodemask = NULL;
  size_t i = 0;
  int ret = 0;
  int savederrno = 0;

  libcrun_debug ("Initializing linux numa mempolicy");

  if (def->linux && def->linux->memory_policy)
    {
      memory_policy = def->linux->memory_policy;

      libcrun_debug ("Checking hardware numa availability");
      if (numa_available () < 0)
        {
          return crun_make_error (err, ENOENT, "linux numa not supported on current hardware");
        }

      libcrun_debug ("Validating linux numa mempolicy");

      /* validate memory policy mode */
      if (! memory_policy->mode)
        {
          return crun_make_error (err, EINVAL, "linux numa mempolicy mode is missing from the configuration");
        }
      libcrun_debug ("Validating mode: %s", memory_policy->mode);
      mpol_mode = mpol_str2int (memory_policy->mode, mpol_mode_map);
      if (mpol_mode < 0)
        {
          return crun_make_error (err, EINVAL, "Requested linux numa mempolicy mode '%s' is unknown", memory_policy->mode);
        }
      mpol_mode_flags = mpol_mode;

      /* both MPOL_DEFAULT and MPOL_LOCAL calls to set_mempolicy expects only
       * the mpol_mode, no nodemask or flags */
      if (mpol_mode != MPOL_DEFAULT && mpol_mode != MPOL_LOCAL)
        {
          /* validating memory policy flags */
          libcrun_debug ("Validating mode flags: %zu configured", memory_policy->flags_len);
          for (i = 0; i < memory_policy->flags_len; i++)
            {
              libcrun_debug ("Validating mode flag: %s", memory_policy->flags[i]);
              mpol_flag = mpol_str2int (memory_policy->flags[i], mpol_flag_map);
              if (mpol_flag < 0)
                {
                  return crun_make_error (err, EINVAL, "Requested linux numa mempolicy flag '%s' is unknown", memory_policy->flags[i]);
                }
              mpol_mode_flags = mpol_mode_flags | mpol_flag;
            }

            /* sanity check mode and flags combinations */
#  if defined MPOL_F_NUMA_BALANCING
          if ((mpol_mode_flags & MPOL_F_NUMA_BALANCING) && mpol_mode != MPOL_BIND)
            {
              return crun_make_error (err, EINVAL, "Requested linux numa mempolicy flag MPOL_F_NUMA_BALANCING is incompatible with %s", memory_policy->mode);
            }
#  endif
#  if defined MPOL_F_RELATIVE_NODES && defined MPOL_F_STATIC_NODES
          if ((mpol_mode_flags & MPOL_F_RELATIVE_NODES) && (mpol_mode_flags & MPOL_F_STATIC_NODES))
            {
              return crun_make_error (err, EINVAL, "Requested linux numa mempolicy flag MPOL_F_RELATIVE_NODES and MPOL_F_STATIC_NODES cannot be combined");
            }
#  endif
          /* validate memory nodes */
          if (! memory_policy->nodes)
            {
              return crun_make_error (err, EINVAL, "linux numa mempolicy nodes is missing from the configuration");
            }
          libcrun_debug ("Validating nodes: %s", memory_policy->nodes);
          /* validation is done by libnuma based on hw environment
           * and numa_warn symbol is overridden in error.c to convert
           * numa logging to libcrun logging */
          nodemask = numa_parse_nodestring_all (memory_policy->nodes);
          if (! nodemask)
            {
              return crun_make_error (err, EINVAL, "numa_parse_nodestring_all validation failed");
            }

          ret = set_mempolicy (mpol_mode_flags, nodemask->maskp, nodemask->size - 1);
          savederrno = errno;
          numa_bitmask_free (nodemask);
          errno = savederrno;
        }
      else
        {
          ret = set_mempolicy (mpol_mode, NULL, 0);
        }

      if (ret < 0)
        {
          return crun_make_error (err, errno, "set_mempolicy: %d errno: %d\n", ret, errno);
        }
    }
  else
    {
      libcrun_debug ("no linux numa mempolicy configuration found");
    }
#endif
  return ret;
}
