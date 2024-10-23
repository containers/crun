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
#ifdef HAVE_LINUX_SCHED_H
#  include <linux/sched.h>
#endif
#ifdef HAVE_SYS_SYSMACROS_H
#  include <sys/sysmacros.h>
#endif
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
    return crun_make_error (err, errno, "sched_setattr");

  return 0;
}
