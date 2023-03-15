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
#include <sys/sysmacros.h>
#include <limits.h>
#include <inttypes.h>

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
libcrun_set_scheduler (pid_t pid, libcrun_container_t *container, libcrun_error_t *err)
{
  cleanup_free char *copy = NULL;
  struct sched_attr_s attr;
  const char *annotation;
  char *v, *v_options;
  int ret, policy;
  char *sptr;
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

  memset (&attr, 0, sizeof (attr));
  attr.size = sizeof (attr);

  annotation = find_annotation (container, "run.oci.scheduler");
  if (LIKELY (annotation == NULL))
    return 0;

  copy = xstrdup (annotation);
  v_options = strchr (copy, '#');
  if (v_options)
    *v_options = '\0';

  policy = -1;
  for (int i = 0; policies[i].name; i++)
    if (strcmp (copy, policies[i].name) == 0)
      {
        policy = policies[i].value;
        break;
      }
  if (UNLIKELY (policy == -1))
    return crun_make_error (err, 0, "invalid scheduler `%s`", copy);

  attr.sched_policy = policy;

  if (v_options)
    {
      v_options++;
      for (v = strtok_r (v_options, "#", &sptr); v; v = strtok_r (NULL, "#", &sptr))
        {
          char *key = v;
          char *value;
          char *ep = NULL;

          value = strchr (v, ':');
          if (UNLIKELY (value == NULL))
            return crun_make_error (err, 0, "invalid scheduler option `%s`", v);
          *value++ = '\0';

          if (strcmp (key, "flag_reset_on_fork") == 0)
            attr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
          else if (strcmp (key, "flag_reclaim") == 0)
            attr.sched_flags |= SCHED_FLAG_RECLAIM;
          else if (strcmp (key, "flag_dl_overrun") == 0)
            attr.sched_flags |= SCHED_FLAG_DL_OVERRUN;
          else if (strcmp (key, "flag_keep_policy") == 0)
            attr.sched_flags |= SCHED_FLAG_KEEP_POLICY;
          else if (strcmp (key, "flag_keep_params") == 0)
            attr.sched_flags |= SCHED_FLAG_KEEP_PARAMS;
          else if (strcmp (key, "flag_util_clamp_min") == 0)
            attr.sched_flags |= SCHED_FLAG_UTIL_CLAMP_MIN;
          else if (strcmp (key, "flag_util_clamp_max") == 0)
            attr.sched_flags |= SCHED_FLAG_UTIL_CLAMP_MAX;
          else if (strcmp (key, "prio") == 0)
            {

              errno = 0;
              attr.sched_priority = strtoul (value, &ep, 10);
              if (UNLIKELY (ep != NULL && *ep != '\0'))
                return crun_make_error (err, EINVAL, "parse scheduler annotation");
              if (UNLIKELY (errno))
                return crun_make_error (err, errno, "parse scheduler annotation");

              if (attr.sched_priority < (uint32_t) sched_get_priority_min (policy)
                  || attr.sched_priority > (uint32_t) sched_get_priority_max (policy))
                return crun_make_error (err, 0, "scheduler priority value `%ul` out of range", attr.sched_priority);
            }
          else if (strcmp (key, "runtime") == 0)
            {
              attr.sched_runtime = strtoull (value, &ep, 10);
              if (UNLIKELY (ep != NULL && *ep != '\0'))
                return crun_make_error (err, EINVAL, "parse scheduler annotation");
              if (UNLIKELY (errno))
                return crun_make_error (err, errno, "parse scheduler annotation");
            }
          else if (strcmp (key, "deadline") == 0)
            {
              attr.sched_deadline = strtoull (value, &ep, 10);
              if (UNLIKELY (ep != NULL && *ep != '\0'))
                return crun_make_error (err, EINVAL, "parse scheduler annotation");
              if (UNLIKELY (errno))
                return crun_make_error (err, errno, "parse scheduler annotation");
            }
          else if (strcmp (key, "period") == 0)
            {
              attr.sched_period = strtoull (value, &ep, 10);
              if (UNLIKELY (ep != NULL && *ep != '\0'))
                return crun_make_error (err, EINVAL, "parse scheduler annotation");
              if (UNLIKELY (errno))
                return crun_make_error (err, errno, "parse scheduler annotation");
            }
          else
            {
              return crun_make_error (err, 0, "invalid scheduler option `%s`", key);
            }
        }
    }

  ret = syscall_sched_setattr (pid, &attr, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sched_setattr");

  return 0;
}
