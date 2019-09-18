/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static int
syscall_seccomp (unsigned int operation, unsigned int flags, void *args)
{
  return (int) syscall (__NR_seccomp, operation, flags, args);
}

unsigned long
get_seccomp_operator (const char *name, libcrun_error_t *err)
{
  if (strcmp (name, "SCMP_CMP_NE") == 0)
    return SCMP_CMP_NE;
  if (strcmp (name, "SCMP_CMP_LT") == 0)
    return SCMP_CMP_LT;
  if (strcmp (name, "SCMP_CMP_LE") == 0)
    return SCMP_CMP_LE;
  if (strcmp (name, "SCMP_CMP_EQ") == 0)
    return SCMP_CMP_EQ;
  if (strcmp (name, "SCMP_CMP_GE") == 0)
    return SCMP_CMP_GE;
  if (strcmp (name, "SCMP_CMP_GT") == 0)
    return SCMP_CMP_GT;
  if (strcmp (name, "SCMP_CMP_MASKED_EQ") == 0)
    return SCMP_CMP_MASKED_EQ;

  crun_make_error (err, 0, "seccomp get operator", name);
  return 0;
}

unsigned long long
get_seccomp_action (const char *name, libcrun_error_t *err)
{
  if (strcmp (name, "SCMP_ACT_KILL") == 0)
    return SCMP_ACT_KILL;
  if (strcmp (name, "SCMP_ACT_ALLOW") == 0)
    return SCMP_ACT_ALLOW;
  if (strcmp (name, "SCMP_ACT_TRAP") == 0)
    return SCMP_ACT_TRAP;
  if (strcmp (name, "SCMP_ACT_ERRNO") == 0)
    return SCMP_ACT_ERRNO (EPERM);
  if (strcmp (name, "SCMP_ACT_TRACE") == 0)
    return SCMP_ACT_TRACE (EPERM);

  crun_make_error (err, 0, "seccomp get action", name);
  return 0;
}

static void
make_lowercase (char *str)
{
  while (*str)
    {
      *str = tolower (*str);
      str++;
    }
}

static void
cleanup_seccompp (void *p)
{
  scmp_filter_ctx *ctx = (void **) p;
  if (*ctx)
    seccomp_release (*ctx);
}
#define cleanup_seccomp __attribute__((cleanup (cleanup_seccompp)))

int
libcrun_apply_seccomp (int infd, char **seccomp_flags, size_t seccomp_flags_len, libcrun_error_t *err)
{
  int ret;
  struct sock_fprog seccomp_filter;
  cleanup_free char *bpf = NULL;
  unsigned int flags = 0;
  size_t len;

  if (infd < 0)
    return 0;


  /* if no seccomp flag was specified use a sane default.  */
  if (seccomp_flags == NULL)
    flags = SECCOMP_FILTER_FLAG_LOG|SECCOMP_FILTER_FLAG_SPEC_ALLOW;
  else
    {
      size_t i = 0;
      for (i = 0; i < seccomp_flags_len; i++)
        {
          if (strcmp (seccomp_flags[i], "SECCOMP_FILTER_FLAG_TSYNC") == 0)
              flags |= SECCOMP_FILTER_FLAG_TSYNC;
          else if (strcmp (seccomp_flags[i], "SECCOMP_FILTER_FLAG_SPEC_ALLOW") == 0)
            flags |= SECCOMP_FILTER_FLAG_SPEC_ALLOW;
          else if (strcmp (seccomp_flags[i], "SECCOMP_FILTER_FLAG_LOG") == 0)
            flags |= SECCOMP_FILTER_FLAG_LOG;
          else
            return crun_make_error (err, 0, "unknown seccomp option %s", seccomp_flags[i]);
        }
    }

  ret = read_all_fd (infd, "seccomp.bpf", &bpf, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  seccomp_filter.len = len / 8;
  seccomp_filter.filter = (struct sock_filter *) bpf;

  ret = syscall_seccomp (SECCOMP_SET_MODE_FILTER, flags, &seccomp_filter);
  if (UNLIKELY (ret < 0))
    {
      /* If any of the flags is not supported, try again without specifying them:  */
      if (errno == EINVAL)
        ret = syscall_seccomp (SECCOMP_SET_MODE_FILTER, 0, &seccomp_filter);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "seccomp (SECCOMP_SET_MODE_FILTER)");
    }

  return 0;
}

int
libcrun_generate_and_load_seccomp (libcrun_container_t *container, int outfd, char **flags, size_t flags_len, libcrun_error_t *err)
{
  oci_container_linux_seccomp *seccomp = container->container_def->linux->seccomp;
  int ret;
  size_t i;
  cleanup_seccomp scmp_filter_ctx ctx = NULL;
  int action, default_action;
  const char *def_action = "SCMP_ACT_ALLOW";

  if (seccomp == NULL)
    return 0;

  /* seccomp not available.  */
  if (prctl (PR_GET_SECCOMP, 0, 0, 0, 0) < 0)
    return crun_make_error (err, errno, "prctl");

  if (seccomp->default_action != NULL)
    def_action = seccomp->default_action;

  default_action = get_seccomp_action (def_action, err);
  if (UNLIKELY (default_action == 0))
    return crun_make_error (err, 0, "invalid seccomp action '%s'", seccomp->default_action);

  ctx = seccomp_init (default_action);
  if (ctx == NULL)
    return crun_make_error (err, 0, "error seccomp_init");

  for (i = 0; i < seccomp->architectures_len; i++)
    {
      uint32_t arch_token;
      const char *arch = seccomp->architectures[i];
      char lowercase_arch[32];

      if (has_prefix (arch, "SCMP_ARCH_"))
        arch += 10;
      stpncpy (lowercase_arch, arch, sizeof (lowercase_arch));
      make_lowercase (lowercase_arch);
#ifdef SECCOMP_ARCH_RESOLVE_NAME
      arch_token = seccomp_arch_resolve_name (lowercase_arch);
      if (arch_token == 0)
        return crun_make_error (err, 0, "seccomp unknown architecture %s", arch);
#else
      arch_token = SCMP_ARCH_NATIVE;
#endif
      ret = seccomp_arch_add (ctx, arch_token);
      if (ret < 0 && ret != -EEXIST)
        return crun_make_error (err, 0, "seccomp adding architecture");
    }

  for (i = 0; i < seccomp->syscalls_len; i++)
    {
      size_t j;
      action = get_seccomp_action (seccomp->syscalls[i]->action, err);
      if (UNLIKELY (action == 0))
        return crun_make_error (err, 0, "invalid seccomp action '%s'", seccomp->syscalls[i]->action);

      if (action == default_action)
        continue;

      for (j = 0; j < seccomp->syscalls[i]->names_len; j++)
        {
          int syscall = seccomp_syscall_resolve_name (seccomp->syscalls[i]->names[j]);

          if (UNLIKELY (syscall == __NR_SCMP_ERROR))
            return crun_make_error (err, 0, "invalid seccomp syscall '%s'", seccomp->syscalls[i]->names[j]);

          if (seccomp->syscalls[i]->args == NULL)
            {
              ret = seccomp_rule_add (ctx, action, syscall, 0);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, -ret, "seccomp_rule_add '%s'", seccomp->syscalls[i]->names[j]);
            }
          else
            {
              size_t k;
              struct scmp_arg_cmp arg_cmp[6];
              for (k = 0; k < seccomp->syscalls[i]->args_len && k < 6; k++)
                {
                  char *op = seccomp->syscalls[i]->args[k]->op;

                  arg_cmp[k].arg = k;
                  arg_cmp[k].op = get_seccomp_operator (op, err);
                  if (arg_cmp[k].op == 0)
                    return crun_make_error (err, 0, "get_seccomp_operator");
                  arg_cmp[k].datum_a = seccomp->syscalls[i]->args[k]->value;
                  arg_cmp[k].datum_b = seccomp->syscalls[i]->args[k]->value_two;
                }
              ret = seccomp_rule_add_array (ctx,
                                            action,
                                            syscall,
                                            k,
                                            arg_cmp);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, 0, "seccomp_rule_add_array");
            }
        }
    }

  if (outfd >= 0)
    {
      ret = seccomp_export_bpf (ctx, outfd);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "seccomp_export_bpf");
    }

  if (UNLIKELY (lseek (outfd, 0, SEEK_SET) == (off_t) -1))
    return crun_make_error (err, 0, "lseek");

  return libcrun_apply_seccomp (outfd, flags, flags_len, err);
}
