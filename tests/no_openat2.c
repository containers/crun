/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2026 crun Authors
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
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

/* Install a seccomp filter that makes openat2(2) fail with ENOSYS, then exec
   the given command.  The filter is inherited across exec() and by every
   child process, so running the test suite under this helper:

       ./tests/no_openat2 make check

   exercises the safe_openat() fallback path used on kernels older than 5.6,
   as well as on any kernel where a seccomp filter blocks openat2.

   Note that without CAP_SYS_ADMIN the filter can only be installed after
   NO_NEW_PRIVS is set, and NO_NEW_PRIVS is inherited by the containers
   created by the test suite; tests looking at noNewPrivileges fail in that
   case.  For this reason the test suite is run under this helper only as
   root.  */

#define _GNU_SOURCE

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_openat2
#  define __NR_openat2 437
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#  define SECCOMP_SET_MODE_FILTER 1
#endif

static int
install_filter (void)
{
  struct sock_filter filter[] = {
    /* Load the syscall number.  */
    BPF_STMT (BPF_LD | BPF_W | BPF_ABS, offsetof (struct seccomp_data, nr)),
    /* If it is not openat2, allow it.  */
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, __NR_openat2, 0, 1),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
    .len = (unsigned short) (sizeof (filter) / sizeof (filter[0])),
    .filter = filter,
  };

  if (syscall (__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == 0)
    return 0;

  /* Without CAP_SYS_ADMIN the filter can only be installed after
     NO_NEW_PRIVS is set.  */
  if (errno != EACCES)
    return -1;

  if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    return -1;

  return syscall (__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}

int
main (int argc, char **argv)
{
  if (argc < 2)
    {
      fprintf (stderr, "usage: %s COMMAND [ARGS...]\n", argv[0]);
      return 2;
    }

  if (install_filter () < 0)
    {
      fprintf (stderr, "%s: cannot install seccomp filter: %s\n", argv[0], strerror (errno));
      return 2;
    }

  execvp (argv[1], argv + 1);

  fprintf (stderr, "%s: exec `%s`: %s\n", argv[0], argv[1], strerror (errno));
  return 127;
}
