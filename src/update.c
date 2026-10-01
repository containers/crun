/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "crun.h"

static char doc[] = "OCI runtime";

static char *resources = NULL;

enum
{
  FIRST_VALUE = 1000,

  BLKIO_WEIGHT = FIRST_VALUE,

  CPU_PERIOD,
  CPU_QUOTA,
  CPU_SHARE,
  CPU_RT_PERIOD,
  CPU_RT_RUNTIME,
  CPU_BURST,
  CPU_IDLE,
  CPUSET_CPUS,
  CPUSET_MEMS,

  KERNEL_MEMORY,
  KERNEL_MEMORY_TCP,
  MEMORY,
  MEMORY_RESERVATION,
  MEMORY_SWAP,

  PIDS_LIMIT,

  /* not in the resources block.  */
  L3_CACHE_SCHEMA,
  MEM_BW_SCHEMA,

  LAST_VALUE,
};

struct description_s
{
  int id;
  const char *section;
  const char *name;
  int numeric;
};

static struct description_s descriptors[] = { { BLKIO_WEIGHT, "blockIO", "weight", 1 },

                                              { CPU_PERIOD, "cpu", "period", 1 },
                                              { CPU_QUOTA, "cpu", "quota", 1 },
                                              { CPU_SHARE, "cpu", "shares", 1 },
                                              { CPU_RT_PERIOD, "cpu", "realtimePeriod", 1 },
                                              { CPU_RT_RUNTIME, "cpu", "realtimeRuntime", 1 },
                                              { CPU_BURST, "cpu", "burst", 1 },
                                              { CPU_IDLE, "cpu", "idle", 1 },
                                              { CPUSET_CPUS, "cpu", "cpus", 0 },
                                              { CPUSET_MEMS, "cpu", "mems", 0 },

                                              { KERNEL_MEMORY, "memory", "kernel", 1 },
                                              { KERNEL_MEMORY_TCP, "memory", "kernelTCP", 1 },
                                              { MEMORY, "memory", "limit", 1 },
                                              { MEMORY_RESERVATION, "memory", "reservation", 1 },
                                              { MEMORY_SWAP, "memory", "swap", 1 },

                                              { PIDS_LIMIT, "pids", "limit", 1 },
                                              { 0 } };

static struct libcrun_update_value_s *values;
size_t values_len = 0;

static void
set_value (int id, const char *value)
{
  values = xrealloc (values, (values_len + 1) * sizeof (struct libcrun_update_value_s));
  values[values_len].section = descriptors[id - FIRST_VALUE].section;
  values[values_len].name = descriptors[id - FIRST_VALUE].name;
  values[values_len].numeric = descriptors[id - FIRST_VALUE].numeric;
  values[values_len].value = value;
  values_len++;
}

/* Parse a memory size, which may have a unit suffix (e.g. 512k or 1.5G),
   like runc does.  Return the size in bytes as a string.  */
static char *
parse_memory_size (const char *opt, const char *value)
{
  const char *suffix;
  char buf[32];
  char *end;
  double size, mul = 1;

  if (strcmp (value, "-1") == 0)
    return xstrdup (value);

  errno = 0;
  size = strtod (value, &end);
  if ((value[0] != '.' && (value[0] < '0' || value[0] > '9')) || end == value || errno != 0 || size < 0)
    goto invalid;

  suffix = end;
  if (*suffix == ' ')
    suffix++;
  if (*suffix)
    {
      switch (*suffix | 0x20)
        {
        case 'b':
          if (suffix[1] != '\0')
            goto invalid;
          break;
        case 'k':
          mul = 1ULL << 10;
          break;
        case 'm':
          mul = 1ULL << 20;
          break;
        case 'g':
          mul = 1ULL << 30;
          break;
        case 't':
          mul = 1ULL << 40;
          break;
        case 'p':
          mul = 1ULL << 50;
          break;
        default:
          goto invalid;
        }
      if (mul > 1 && suffix[1] != '\0' && strcasecmp (suffix + 1, "b") != 0 && strcasecmp (suffix + 1, "ib") != 0)
        goto invalid;
    }

  size *= mul;
  if (size >= 9223372036854775808.0)
    goto invalid;

  snprintf (buf, sizeof (buf), "%lld", (long long) size);
  return xstrdup (buf);

invalid:
  libcrun_fail_with_error (0, "invalid value for --%s: `%s`", opt, value);
}

/* Check that VALUE is an integer.  */
static const char *
check_integer (const char *opt, const char *value)
{
  char *end;

  errno = 0;
  (void) strtoll (value, &end, 10);
  if (end == value || *end != '\0' || errno != 0)
    libcrun_fail_with_error (0, "invalid value for --%s: `%s`", opt, value);
  return value;
}

static char *l3_cache_schema;
static char *mem_bw_schema;

static struct argp_option options[]
    = { { "resources", 'r', "FILE", 0, "path to the file containing the resources to update", 0 },
        { "blkio-weight", BLKIO_WEIGHT, "VALUE", 0, "Specifies per cgroup weight", 0 },
        { "cpu-period", CPU_PERIOD, "VALUE", 0, "CPU CFS period to be used for hardcapping", 0 },
        { "cpu-quota", CPU_QUOTA, "VALUE", 0, "CPU CFS hardcap limit", 0 },
        { "cpu-share", CPU_SHARE, "VALUE", 0, "CPU shares", 0 },
        { "cpu-rt-period", CPU_RT_PERIOD, "VALUE", 0, "CPU realtime period to be used for hardcapping", 0 },
        { "cpu-rt-runtime", CPU_RT_RUNTIME, "VALUE", 0, "CPU realtime hardcap limit", 0 },
        { "cpu-burst", CPU_BURST, "VALUE", 0, "CPU CFS burst limit", 0 },
        { "cpu-idle", CPU_IDLE, "VALUE", 0, "set cgroup SCHED_IDLE or not, 0: default behavior, 1: SCHED_IDLE", 0 },
        { "cpuset-cpus", CPUSET_CPUS, "VALUE", 0, "CPU(s) to use", 0 },
        { "cpuset-mems", CPUSET_MEMS, "VALUE", 0, "Memory node(s) to use", 0 },
        { "kernel-memory", KERNEL_MEMORY, "VALUE", 0, "Kernel memory limit", 0 },
        { "kernel-memory-tcp", KERNEL_MEMORY_TCP, "VALUE", 0, "Kernel memory limit for tcp buffer", 0 },
        { "memory", MEMORY, "VALUE", 0, "Memory limit", 0 },
        { "memory-reservation", MEMORY_RESERVATION, "VALUE", 0, "Memory reservation or soft_limit", 0 },
        { "memory-swap", MEMORY_SWAP, "VALUE", 0, "Total memory usage", 0 },
        { "pids-limit", PIDS_LIMIT, "VALUE", 0, "Maximum number of pids allowed in the container", 0 },
        { "l3-cache-schema", L3_CACHE_SCHEMA, "VALUE", 0, "The string of Intel RDT/CAT L3 cache schema", 0 },
        { "mem-bw-schema", MEM_BW_SCHEMA, "VALUE", 0, "The string of Intel RDT/MBA memory bandwidth schema", 0 },
        {
            0,
        } };

static char args_doc[] = "update [OPTION]... CONTAINER";

static const char *
option_name (int key)
{
  size_t i;

  for (i = 0; options[i].name; i++)
    if (options[i].key == key)
      return options[i].name;
  return "";
}

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'r':
      resources = argp_mandatory_argument (arg, state);
      break;

    case ARGP_KEY_NO_ARGS:
      libcrun_fail_with_error (0, "please specify a ID for the container");

    case CPUSET_CPUS:
    case CPUSET_MEMS:
      set_value (key, argp_mandatory_argument (arg, state));
      break;

    case BLKIO_WEIGHT:
    case CPU_PERIOD:
    case CPU_QUOTA:
    case CPU_SHARE:
    case CPU_RT_PERIOD:
    case CPU_RT_RUNTIME:
    case CPU_BURST:
    case CPU_IDLE:
    case PIDS_LIMIT:
      set_value (key, check_integer (option_name (key), argp_mandatory_argument (arg, state)));
      break;

    case KERNEL_MEMORY:
    case KERNEL_MEMORY_TCP:
    case MEMORY:
    case MEMORY_RESERVATION:
    case MEMORY_SWAP:
      set_value (key, parse_memory_size (option_name (key), argp_mandatory_argument (arg, state)));
      break;

    case L3_CACHE_SCHEMA:
      l3_cache_schema = argp_mandatory_argument (arg, state);
      break;

    case MEM_BW_SCHEMA:
      mem_bw_schema = argp_mandatory_argument (arg, state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

/* If the memory limit is removed and no swap limit is given, remove the
   swap limit as well (which cannot be larger than the memory one), like
   runc does.  */
static void
set_swap_for_unlimited_memory (void)
{
  bool unlimited_memory = false;
  size_t i;

  for (i = 0; i < values_len; i++)
    {
      if (strcmp (values[i].section, "memory") != 0)
        continue;
      if (strcmp (values[i].name, "swap") == 0)
        return;
      if (strcmp (values[i].name, "limit") == 0)
        unlimited_memory = strcmp (values[i].value, "-1") == 0;
    }

  if (unlimited_memory)
    set_value (MEMORY_SWAP, "-1");
}

static struct argp run_argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

int
crun_command_update (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg = 0, ret;
  cleanup_context libcrun_context_t *crun_context = NULL;

  /* Allow options after the container ID, like runc does.  */
  argp_parse (&run_argp, argc, argv, 0, &first_arg, NULL);
  crun_assert_n_args (argc - first_arg, 1, 1);

  set_swap_for_unlimited_memory ();

  crun_context = new_libcrun_context (global_args);

  ret = init_libcrun_context (crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (resources == NULL)
    {
      ret = libcrun_container_update_from_values (crun_context, argv[first_arg], values, values_len, err);
      free (values);
      if (ret < 0)
        return ret;
    }
  else
    {
      ret = libcrun_container_update_from_file (crun_context, argv[first_arg], resources, err);
      if (ret < 0)
        return ret;
    }

  if (l3_cache_schema || mem_bw_schema)
    {
      struct libcrun_intel_rdt_update update = {
        .l3_cache_schema = l3_cache_schema,
        .mem_bw_schema = mem_bw_schema,
      };

      ret = libcrun_container_update_intel_rdt (crun_context, argv[first_arg], &update, err);
      if (ret < 0)
        return ret;
    }

  return 0;
}
