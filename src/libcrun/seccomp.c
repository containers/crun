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
#include "seccomp.h"
#include "linux.h"
#include "utils.h"
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#if HAVE_GCRYPT
#  include <gcrypt.h>
#endif

#if HAVE_STDATOMIC_H
#  include <stdatomic.h>
#else
#  define atomic_int volatile int
#endif

#ifdef HAVE_SECCOMP
#  include <seccomp.h>
#endif
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#ifndef __NR_seccomp
#  define __NR_seccomp 0xffff // seccomp syscall number unknown for this architecture
#endif

#ifndef SECCOMP_SET_MODE_STRICT
#  define SECCOMP_SET_MODE_STRICT 0
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#  define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#  define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif

#ifndef SECCOMP_FILTER_FLAG_LOG
#  define SECCOMP_FILTER_FLAG_LOG (1UL << 1)
#endif

#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
#  define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1UL << 2)
#endif

#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#  define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)
#endif

static int
syscall_seccomp (unsigned int operation, unsigned int flags, void *args)
{
  return (int) syscall (__NR_seccomp, operation, flags, args);
}

static unsigned long
get_seccomp_operator (const char *name, libcrun_error_t *err)
{
#ifdef HAVE_SECCOMP
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

  crun_make_error (err, 0, "seccomp get operator `%s`", name);
  return 0;
#else
  return 0;
#endif
}

static unsigned long long
get_seccomp_action (const char *name, int errno_ret, libcrun_error_t *err)
{
#ifdef HAVE_SECCOMP
  const char *p;

  p = name;
  if (strncmp (p, "SCMP_ACT_", 9))
    goto fail;

  p += 9;

  if (strcmp (p, "ALLOW") == 0)
    return SCMP_ACT_ALLOW;
  else if (strcmp (p, "ERRNO") == 0)
    return SCMP_ACT_ERRNO (errno_ret);
  else if (strcmp (p, "KILL") == 0)
    return SCMP_ACT_KILL;
#  ifdef SCMP_ACT_LOG
  else if (strcmp (p, "LOG") == 0)
    return SCMP_ACT_LOG;
#  endif
  else if (strcmp (p, "TRAP") == 0)
    return SCMP_ACT_TRAP;
  else if (strcmp (p, "TRACE") == 0)
    return SCMP_ACT_TRACE (errno_ret);
#  ifdef SCMP_ACT_KILL_PROCESS
  else if (strcmp (p, "KILL_PROCESS") == 0)
    return SCMP_ACT_KILL_PROCESS;
#  endif
#  ifdef SCMP_ACT_KILL_THREAD
  else if (strcmp (p, "KILL_THREAD") == 0)
    return SCMP_ACT_KILL_THREAD;
#  endif
#  ifdef SCMP_ACT_NOTIFY
  else if (strcmp (p, "NOTIFY") == 0)
    return SCMP_ACT_NOTIFY;
#  endif

fail:
  crun_make_error (err, 0, "seccomp get action `%s`", name);
  return 0;
#else
  return 0;
#endif
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
#ifdef HAVE_SECCOMP
  scmp_filter_ctx *ctx = (void **) p;
  if (*ctx)
    seccomp_release (*ctx);
#endif
}
#define cleanup_seccomp __attribute__ ((cleanup (cleanup_seccompp)))

int
libcrun_apply_seccomp (int infd, int listener_receiver_fd, const char *receiver_fd_payload,
                       size_t receiver_fd_payload_len, char **seccomp_flags, size_t seccomp_flags_len,
                       libcrun_error_t *err)
{
#ifdef HAVE_SECCOMP
  cleanup_mmap struct libcrun_mmap_s *mmap_region = NULL;
  cleanup_close int listener_fd = -1;
  cleanup_pid int helper_proc = -1;
  struct sock_fprog seccomp_filter;
  cleanup_free char *bpf = NULL;
  unsigned int flags = 0;
  size_t len;
  int ret;

  if (infd < 0)
    return 0;

  if (UNLIKELY (lseek (infd, 0, SEEK_SET) == (off_t) -1))
    return crun_make_error (err, errno, "lseek");

  /* if no seccomp flag was specified use a sane default.  */
  if (seccomp_flags == NULL)
    flags = SECCOMP_FILTER_FLAG_SPEC_ALLOW;
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
          else if (strcmp (seccomp_flags[i], "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV") == 0)
            flags |= SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
          else
            return crun_make_error (err, 0, "unknown seccomp option %s", seccomp_flags[i]);
        }
    }

  ret = read_all_fd (infd, "seccomp.bpf", &bpf, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  seccomp_filter.len = len / 8;
  seccomp_filter.filter = (struct sock_filter *) bpf;

  if (listener_receiver_fd >= 0)
    {
      cleanup_close int memfd = -1;
      atomic_int *fd_received;

#  ifdef SECCOMP_FILTER_FLAG_NEW_LISTENER
      flags |= SECCOMP_FILTER_FLAG_NEW_LISTENER;
#  else
      return crun_make_error (err, 0, "the SECCOMP_FILTER_FLAG_NEW_LISTENER flag is not supported");
#  endif

      memfd = memfd_create ("seccomp-helper-memfd", O_RDWR);
      if (UNLIKELY (memfd < 0))
        return crun_make_error (err, errno, "memfd_create");

      ret = ftruncate (memfd, sizeof (atomic_int));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "ftruncate seccomp memfd");

      ret = libcrun_mmap (&mmap_region, NULL, sizeof (atomic_int),
                          PROT_WRITE | PROT_READ, MAP_SHARED, memfd, 0, err);
      if (UNLIKELY (ret < 0))
        return ret;

      /* memfd is not needed anymore.  */
      close_and_reset (&memfd);

      fd_received = mmap_region->addr;
      *fd_received = -1;

      /* The helper process shares the fd table with the current process.  */
      helper_proc = syscall_clone (CLONE_FILES | SIGCHLD, NULL);
      if (UNLIKELY (helper_proc < 0))
        return crun_make_error (err, errno, "clone seccomp listener helper process");

      /* helper process.  Wait that the seccomp listener fd is created then send it to the
         receiver fd.  We use the helper process since the seccomp profile could block the
         sendmsg syscall.   Its exit status is an errno value.  */
      if (helper_proc == 0)
        {
          int fd, timeout = 0;

          prctl (PR_SET_PDEATHSIG, SIGKILL);
          for (;;)
            {
              fd = *fd_received;
              if (fd == -1)
                {
                  usleep (1000);

                  /* Do not wait longer than 5 seconds.  */
                  if (timeout++ > 5000)
                    _exit (EINVAL);
                  continue;
                }
#  if ! HAVE_STDATOMIC_H
              /* If stdatomic is not available, force a membarrier and read again.  */
              __sync_synchronize ();
              fd = *fd_received;
#  endif
              break;
            }
          ret = send_fd_to_socket_with_payload (listener_receiver_fd, fd,
                                                receiver_fd_payload,
                                                receiver_fd_payload_len,
                                                err);
          if (UNLIKELY (ret < 0))
            _exit (crun_error_get_errno (err));
          _exit (0);
        }
    }

  ret = syscall_seccomp (SECCOMP_SET_MODE_FILTER, flags, &seccomp_filter);
  if (UNLIKELY (ret < 0))
    {
      /* If any of the flags is not supported, try again without specifying them:  */
      if (errno == EINVAL && listener_receiver_fd < 0)
        ret = syscall_seccomp (SECCOMP_SET_MODE_FILTER, 0, &seccomp_filter);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "seccomp (SECCOMP_SET_MODE_FILTER)");
    }

  if (listener_receiver_fd >= 0)
    {
      atomic_int *fd_to_send = mmap_region->addr;
      int status = 0;

      /* Write atomically the listener fd to the shared memory.  No syscalls are used between
         the seccomp listener creation and the write.  */
      *fd_to_send = listener_fd = ret;

      ret = waitpid_ignore_stopped (helper_proc, &status, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "waitpid seccomp listener helper process");

      ret = get_process_exit_status (status);
      if (ret != 0)
        return crun_make_error (err, ret, "send listener fd `%d` to receiver", listener_fd);
    }

  return 0;
#else
  return 0;
#endif
}

static bool
seccomp_action_supports_errno (const char *action)
{
  return strcmp (action, "SCMP_ACT_ERRNO") == 0
         || strcmp (action, "SCMP_ACT_TRACE") == 0;
}

static int
calculate_seccomp_checksum (libcrun_container_t *container, unsigned int seccomp_gen_options, seccomp_checksum_t out, libcrun_error_t *err)
{
#if HAVE_GCRYPT
  runtime_spec_schema_config_linux_seccomp *seccomp;
  gcry_error_t gcrypt_err;
  unsigned char *res;
  gcry_md_hd_t hd;
  size_t i;

#  define PROCESS_STRING(X)                      \
    do                                           \
      {                                          \
        if (X)                                   \
          {                                      \
            gcry_md_write (hd, (X), strlen (X)); \
          }                                      \
    } while (0)
#  define PROCESS_DATA(X)                     \
    do                                        \
      {                                       \
        gcry_md_write (hd, &(X), sizeof (X)); \
    } while (0)

  out[0] = 0;

  if (container == NULL || container->container_def == NULL || container->container_def->linux == NULL)
    return 0;

  seccomp = container->container_def->linux->seccomp;
  if (seccomp == NULL)
    return 0;

  gcrypt_err = gcry_md_open (&hd, GCRY_MD_SHA256, 0);
  if (gcrypt_err)
    return crun_make_error (err, EINVAL, "internal libgcrypt error: %s", gcry_strerror (gcrypt_err));

  PROCESS_STRING (PACKAGE_VERSION);

#  ifdef HAVE_SECCOMP
  {
    const struct scmp_version *version = seccomp_version ();

    PROCESS_DATA (version->major);
    PROCESS_DATA (version->minor);
    PROCESS_DATA (version->micro);
  }
#  endif

  PROCESS_DATA (seccomp_gen_options);

  PROCESS_STRING (seccomp->default_action);
  for (i = 0; i < seccomp->flags_len; i++)
    PROCESS_STRING (seccomp->flags[i]);
  for (i = 0; i < seccomp->architectures_len; i++)
    PROCESS_STRING (seccomp->architectures[i]);
  for (i = 0; i < seccomp->syscalls_len; i++)
    {
      size_t j;

      if (seccomp->syscalls[i]->action)
        PROCESS_STRING (seccomp->syscalls[i]->action);
      for (j = 0; j < seccomp->syscalls[i]->names_len; j++)
        PROCESS_STRING (seccomp->syscalls[i]->names[j]);
      for (j = 0; j < seccomp->syscalls[i]->args_len; j++)
        {
          if (seccomp->syscalls[i]->args[j]->index_present)
            PROCESS_DATA (seccomp->syscalls[i]->args[j]->index);
          if (seccomp->syscalls[i]->args[j]->value_present)
            PROCESS_DATA (seccomp->syscalls[i]->args[j]->value);
          if (seccomp->syscalls[i]->args[j]->value_two_present)
            PROCESS_DATA (seccomp->syscalls[i]->args[j]->value_two);
          PROCESS_STRING (seccomp->syscalls[i]->args[j]->op);
        }
    }

  res = gcry_md_read (hd, GCRY_MD_SHA256);
  for (i = 0; i < 32; i++)
    sprintf (&out[i * 2], "%02x", res[i]);
  out[64] = 0;

  gcry_md_close (hd);

#  undef PROCESS_STRING
#  undef PROCESS_DATA
#else
  (void) container;
  (void) seccomp_gen_options;
  (void) out;
  (void) err;
  out[0] = 0;
#endif
  return 0;
}

int
libcrun_generate_seccomp (libcrun_container_t *container, int outfd, unsigned int options, libcrun_error_t *err)
{
#ifdef HAVE_SECCOMP
  runtime_spec_schema_config_linux_seccomp *seccomp;
  int ret;
  size_t i;
  cleanup_seccomp scmp_filter_ctx ctx = NULL;
  int action, default_action, default_errno_value = EPERM;
  const char *def_action = NULL;

  if (container == NULL || container->container_def == NULL || container->container_def->linux == NULL)
    return 0;

  seccomp = container->container_def->linux->seccomp;
  if (seccomp == NULL)
    return 0;

  /* seccomp not available.  */
  if (prctl (PR_GET_SECCOMP, 0, 0, 0, 0) < 0)
    return crun_make_error (err, errno, "prctl");

  def_action = seccomp->default_action;
  if (def_action == NULL)
    return crun_make_error (err, 0, "seccomp misses the default action");

  if (seccomp->default_errno_ret_present)
    {
      if (! seccomp_action_supports_errno (def_action))
        return crun_make_error (err, 0, "errno value specified for action `%s`", def_action);

      default_errno_value = seccomp->default_errno_ret;
    }

  default_action = get_seccomp_action (def_action, default_errno_value, err);
  if (UNLIKELY (err && *err != NULL))
    return crun_make_error (err, 0, "invalid seccomp action `%s`", seccomp->default_action);

  ctx = seccomp_init (default_action);
  if (ctx == NULL)
    return crun_make_error (err, 0, "error seccomp_init");

  for (i = 0; i < seccomp->architectures_len; i++)
    {
      uint32_t arch_token;
      const char *arch = seccomp->architectures[i];
      char *end, lowercase_arch[32] = {
        0,
      };

      if (has_prefix (arch, "SCMP_ARCH_"))
        arch += 10;
      end = stpncpy (lowercase_arch, arch, sizeof (lowercase_arch) - 1);
      *end = '\0';
      make_lowercase (lowercase_arch);
#  ifdef SECCOMP_ARCH_RESOLVE_NAME
      arch_token = seccomp_arch_resolve_name (lowercase_arch);
      if (arch_token == 0)
        return crun_make_error (err, 0, "seccomp unknown architecture %s", arch);
#  else
      arch_token = SCMP_ARCH_NATIVE;
#  endif
      ret = seccomp_arch_add (ctx, arch_token);
      if (ret < 0 && ret != -EEXIST)
        return crun_make_error (err, -ret, "seccomp adding architecture");
    }

  for (i = 0; i < seccomp->syscalls_len; i++)
    {
      size_t j;
      int errno_ret = EPERM;

      if (seccomp->syscalls[i]->errno_ret_present)
        {
          if (! seccomp_action_supports_errno (seccomp->syscalls[i]->action))
            return crun_make_error (err, 0, "errno value specified for action `%s`", seccomp->syscalls[i]->action);
          errno_ret = seccomp->syscalls[i]->errno_ret;
        }

      action = get_seccomp_action (seccomp->syscalls[i]->action, errno_ret, err);
      if (UNLIKELY (err && *err != NULL))
        return crun_make_error (err, 0, "invalid seccomp action `%s`", seccomp->syscalls[i]->action);

      if (action == default_action)
        continue;

      for (j = 0; j < seccomp->syscalls[i]->names_len; j++)
        {
          int syscall = seccomp_syscall_resolve_name (seccomp->syscalls[i]->names[j]);

          if (UNLIKELY (syscall == __NR_SCMP_ERROR))
            {
              if (options & LIBCRUN_SECCOMP_FAIL_UNKNOWN_SYSCALL)
                return crun_make_error (err, 0, "invalid seccomp syscall `%s`", seccomp->syscalls[i]->names[j]);

              libcrun_warning ("unknown seccomp syscall `%s` ignored", seccomp->syscalls[i]->names[j]);
              continue;
            }

          if (seccomp->syscalls[i]->args == NULL)
            {
              ret = seccomp_rule_add (ctx, action, syscall, 0);
              if (UNLIKELY (ret < 0))
                return crun_make_error (err, -ret, "seccomp_rule_add `%s`", seccomp->syscalls[i]->names[j]);
            }
          else
            {
              size_t k;
              struct scmp_arg_cmp arg_cmp[6];
              bool multiple_args = false;
              uint32_t count[6] = {};

              for (k = 0; k < seccomp->syscalls[i]->args_len && k < 6; k++)
                {
                  uint32_t index;

                  index = seccomp->syscalls[i]->args[k]->index;
                  if (index >= 6)
                    return crun_make_error (err, 0, "invalid seccomp index %zu", i);

                  count[index]++;
                  if (count[index] > 1)
                    {
                      multiple_args = true;
                      break;
                    }
                }

              for (k = 0; k < seccomp->syscalls[i]->args_len && k < 6; k++)
                {
                  char *op = seccomp->syscalls[i]->args[k]->op;

                  arg_cmp[k].arg = seccomp->syscalls[i]->args[k]->index;
                  arg_cmp[k].op = get_seccomp_operator (op, err);
                  if (arg_cmp[k].op == 0)
                    return crun_make_error (err, 0, "get_seccomp_operator");
                  arg_cmp[k].datum_a = seccomp->syscalls[i]->args[k]->value;
                  arg_cmp[k].datum_b = seccomp->syscalls[i]->args[k]->value_two;
                }

              if (! multiple_args)
                {
                  ret = seccomp_rule_add_array (ctx, action, syscall, k, arg_cmp);
                  if (UNLIKELY (ret < 0))
                    return crun_make_error (err, -ret, "seccomp_rule_add_array");
                }
              else
                {
                  size_t r;

                  for (r = 0; r < k; r++)
                    {
                      ret = seccomp_rule_add_array (ctx, action, syscall, 1, &arg_cmp[r]);
                      if (UNLIKELY (ret < 0))
                        return crun_make_error (err, -ret, "seccomp_rule_add_array");
                    }
                }
            }
        }
    }

  if (outfd >= 0)
    {
      ret = seccomp_export_bpf (ctx, outfd);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, "seccomp_export_bpf");
    }

  return 0;
#else
  return 0;
#endif
}
