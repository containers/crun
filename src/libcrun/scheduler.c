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
#include "linux.h"
#include "utils.h"
#include <sched.h>
#include <linux/sched.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <inttypes.h>
#include <ocispec/runtime_spec_schema_config_schema.h>

#ifndef SCHED_FLAG_RESET_ON_FORK
#  define SCHED_FLAG_RESET_ON_FORK 0x01
#endif
#ifndef SCHED_FLAG_RECLAIM
#  define SCHED_FLAG_RECLAIM 0x02
#endif
#ifndef SCHED_FLAG_DL_OVERRUN
#  define SCHED_FLAG_DL_OVERRUN 0x04
#endif
#ifndef SCHED_FLAG_KEEP_POLICY
#  define SCHED_FLAG_KEEP_POLICY 0x08
#endif
#ifndef SCHED_FLAG_KEEP_PARAMS
#  define SCHED_FLAG_KEEP_PARAMS 0x10
#endif
#ifndef SCHED_FLAG_UTIL_CLAMP_MIN
#  define SCHED_FLAG_UTIL_CLAMP_MIN 0x20
#endif
#ifndef SCHED_FLAG_UTIL_CLAMP_MAX
#  define SCHED_FLAG_UTIL_CLAMP_MAX 0x40
#endif

struct sched_attr_s
{
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;

  uint32_t sched_priority;

  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

static int
syscall_sched_setattr (pid_t pid, struct sched_attr_s *attr, unsigned int flags)
{
#ifdef __NR_sched_setattr
  return syscall (__NR_sched_setattr, pid, attr, flags);
#else
  (void) pid;
  (void) attr;
  (void) flags;
  errno = ENOSYS;
  return -1;
#endif
}

int
libcrun_reset_cpu_affinity_mask (pid_t pid, libcrun_error_t *err)
{
  int ret;
  cpu_set_t mask;

  /* Reset the inherited cpu affinity. Old kernels do that automatically, but
     new kernels remember the affinity that was set before the cgroup move.
     This is undesirable, because it inherits the systemd affinity when the container
     should really move to the container space cpus.
     See: https://issues.redhat.com/browse/OCPBUGS-15102   */
  memset (&mask, 0xFF, sizeof (cpu_set_t));
  ret = sched_setaffinity (pid, sizeof (mask), &mask);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sched_setaffinity");
  return 0;
}

static int
diagnose_scheduler_failure (libcrun_error_t *err, runtime_spec_schema_config_schema_process *process,
                            struct sched_attr_s *attr)
{
  if (attr->sched_policy == SCHED_DEADLINE && errno == EINVAL)
    {
      if (! process->scheduler->runtime_present)
        return crun_make_error (err, errno, "sched_setattr: `SCHED_DEADLINE` requires `runtime`");
      if (! process->scheduler->deadline_present)
        return crun_make_error (err, errno, "sched_setattr: `SCHED_DEADLINE` requires `deadline`");

      if (attr->sched_runtime == 0)
        return crun_make_error (err, errno, "sched_setattr: `SCHED_DEADLINE` runtime must be greater than 0");
      if (attr->sched_deadline == 0)
        return crun_make_error (err, errno, "sched_setattr: `SCHED_DEADLINE` deadline must be greater than 0");
      /* Per sched(7), ff sched_period is specified as 0, then it is made the same as sched_deadline. */

      if (attr->sched_runtime > attr->sched_deadline)
        return crun_make_error (err, errno, "sched_setattr: `SCHED_DEADLINE` runtime (%" PRIu64 ") must be <= deadline (%" PRIu64 ")",
                                attr->sched_runtime, attr->sched_deadline);
      if (attr->sched_period != 0 && attr->sched_deadline > attr->sched_period)
        return crun_make_error (err, errno, "sched_setattr: `SCHED_DEADLINE` deadline (%" PRIu64 ") must be <= period (%" PRIu64 ")",
                                attr->sched_deadline, attr->sched_period);

      /* sched(7) says "under the current implementation, all of the parameter values
       * must be at least 1024 <...> and less than 2^63". */
      const uint64_t min = 1024;
      const uint64_t max = 1ULL << 63;

      if (attr->sched_runtime < min || attr->sched_runtime > max)
        return crun_make_error (err, errno, "sched_setattr: `SCHED_DEADLINE` runtime (%" PRIu64 ") must be between %" PRIu64 " and %" PRIu64,
                                attr->sched_runtime, min, max);
      if (attr->sched_deadline < min || attr->sched_deadline > max)
        return crun_make_error (err, errno, "sched_setattr: `SCHED_DEADLINE` deadline (%" PRIu64 ") must be between %" PRIu64 " and %" PRIu64,
                                attr->sched_deadline, min, max);
      if (attr->sched_period != 0 && (attr->sched_period < min || attr->sched_period > max))
        return crun_make_error (err, errno, "sched_setattr: `SCHED_DEADLINE` period (%" PRIu64 ") must be between %" PRIu64 " and %" PRIu64,
                                attr->sched_period, min, max);

      return crun_make_error (err, errno, "sched_setattr: invalid `SCHED_DEADLINE` parameters (runtime=%" PRIu64 ", deadline=%" PRIu64 ", period=%" PRIu64 ")",
                              attr->sched_runtime, attr->sched_deadline, attr->sched_period);
    }

  return crun_make_error (err, errno, "sched_setattr");
}

int
libcrun_set_scheduler (pid_t pid, runtime_spec_schema_config_schema_process *process, libcrun_error_t *err)
{
  struct sched_attr_s attr;
  int i, ret, policy;
  size_t s;
  struct
  {
    const char *name;
    int value;
  } policies[] = {
    { "SCHED_OTHER", SCHED_OTHER },
    { "SCHED_BATCH", SCHED_BATCH },
    { "SCHED_IDLE", SCHED_IDLE },
    { "SCHED_FIFO", SCHED_FIFO },
    { "SCHED_RR", SCHED_RR },
    { "SCHED_DEADLINE", SCHED_DEADLINE },
    { NULL, 0 },
  };

  if (process == NULL || process->scheduler == NULL)
    return 0;

  memset (&attr, 0, sizeof (attr));
  attr.size = sizeof (attr);

  if (is_empty_string (process->scheduler->policy))
    return crun_make_error (err, 0, "scheduler policy not defined");

  policy = -1;
  for (i = 0; policies[i].name; i++)
    if (strcmp (process->scheduler->policy, policies[i].name) == 0)
      {
        policy = i;
        break;
      }
  if (UNLIKELY (policy < 0))
    return crun_make_error (err, 0, "invalid scheduler `%s`", process->scheduler->policy);

  attr.sched_policy = policies[policy].value;

  if (process->scheduler->nice_present)
    attr.sched_nice = process->scheduler->nice;

  if (process->scheduler->priority_present)
    attr.sched_priority = process->scheduler->priority;

  if (process->scheduler->runtime_present)
    attr.sched_runtime = process->scheduler->runtime;

  if (process->scheduler->deadline_present)
    attr.sched_deadline = process->scheduler->deadline;

  if (process->scheduler->period_present)
    attr.sched_period = process->scheduler->period;

  for (s = 0; s < process->scheduler->flags_len; s++)
    {
      char *key = process->scheduler->flags[s];

      if (strcmp (key, "SCHED_FLAG_RESET_ON_FORK") == 0)
        attr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
      else if (strcmp (key, "SCHED_FLAG_RECLAIM") == 0)
        attr.sched_flags |= SCHED_FLAG_RECLAIM;
      else if (strcmp (key, "SCHED_FLAG_DL_OVERRUN") == 0)
        attr.sched_flags |= SCHED_FLAG_DL_OVERRUN;
      else if (strcmp (key, "SCHED_FLAG_KEEP_POLICY") == 0)
        attr.sched_flags |= SCHED_FLAG_KEEP_POLICY;
      else if (strcmp (key, "SCHED_FLAG_KEEP_PARAMS") == 0)
        attr.sched_flags |= SCHED_FLAG_KEEP_PARAMS;
      else if (strcmp (key, "SCHED_FLAG_UTIL_CLAMP_MIN") == 0)
        attr.sched_flags |= SCHED_FLAG_UTIL_CLAMP_MIN;
      else if (strcmp (key, "SCHED_FLAG_UTIL_CLAMP_MAX") == 0)
        attr.sched_flags |= SCHED_FLAG_UTIL_CLAMP_MAX;
      else
        return crun_make_error (err, 0, "invalid scheduler option `%s`", key);
    }

  ret = syscall_sched_setattr (pid, &attr, 0);
  if (UNLIKELY (ret < 0))
    return diagnose_scheduler_failure (err, process, &attr);

  return 0;
}

int
libcrun_set_cpu_affinity_from_string (pid_t pid, const char *str, libcrun_error_t *err)
{
  cleanup_free char *bitmask = NULL;
  int ret, saved_errno;
  size_t bitmask_size;
  cpu_set_t *cpuset;
  size_t alloc_size;
  size_t i;

  if (is_empty_string (str))
    return 0;

  ret = cpuset_string_to_bitmask (str, &bitmask, &bitmask_size, err);
  if (UNLIKELY (ret < 0))
    return ret;

  alloc_size = CPU_ALLOC_SIZE (bitmask_size * CHAR_BIT);

  cpuset = CPU_ALLOC (alloc_size);
  if (UNLIKELY (cpuset == NULL))
    OOM ();

  CPU_ZERO_S (alloc_size, cpuset);

  for (i = 0; i < bitmask_size * CHAR_BIT; i++)
    {
      if (bitmask[i / CHAR_BIT] & (1 << (i % CHAR_BIT)))
        CPU_SET_S (i, alloc_size, cpuset);
    }

  ret = sched_setaffinity (pid, alloc_size, cpuset);
  saved_errno = errno;
  CPU_FREE (cpuset);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, saved_errno, "sched_setaffinity");
  return 0;
}
