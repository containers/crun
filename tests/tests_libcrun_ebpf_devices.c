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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <signal.h>
#include <linux/magic.h>
#ifdef HAVE_EBPF
#  include <linux/bpf.h>
#  include <linux/filter.h>
#  include <linux/seccomp.h>
#  include <sys/prctl.h>
#  include <stddef.h>
#  include <endian.h>
#endif
#include <sys/syscall.h>
#include <libcrun/ebpf.h>
#include <libcrun/cgroup-resources.h>
#include <libcrun/cgroup-internal.h>
#include <libcrun/utils.h>

#include "tap.h"

#ifdef HAVE_EBPF

struct rule
{
  bool allow;
  const char *type;
  int major;
  int minor;
  const char *access;
};

struct scenario
{
  const char *name;
  struct rule *rules;
  size_t n;
};

static struct rule rules_deny_all[] = { { false, "a", -1, -1, "rwm" } };
static struct rule rules_deny_all_allow_null[] = { { false, "a", -1, -1, "rwm" }, { true, "c", 60, 3, "rw" } };
static struct rule rules_allow_major[] = { { true, "c", 61, -1, "rwm" } };
static struct rule rules_allow_all_char[] = { { true, "c", -1, -1, "rm" } };
static struct rule rules_allow_all[] = { { true, "a", -1, -1, "rwm" } };
static struct rule rules_partial_deny[] = { { true, "b", 62, -1, "rwm" }, { false, "b", 62, 3, "w" } };
static struct rule rules_order[] = { { true, "c", 63, -1, "r" }, { false, "c", 63, 7, "rw" }, { true, "c", 63, 7, "w" } };
static struct rule rules_deny_then_allow[] = { { false, "c", 60, 3, "r" }, { true, "c", 60, 3, "rwm" } };
static struct rule rules_empty_access[] = { { true, "c", 120, 1, "" }, { true, "c", 121, 2, "rw" }, { false, "a", -1, -1, "m" } };
static struct rule rules_any_major[] = { { true, "b", -1, 5, "rwm" }, { true, "c", 122, 9, "w" } };
static struct rule rules_allow_all_shadows[] = { { false, "a", -1, -1, "rwm" }, { true, "a", -1, -1, "rwm" }, { false, "c", 60, 3, "rwm" } };
static struct rule rules_any_minor[] = { { true, "b", 62, -1, "r" }, { false, "b", -1, 3, "r" }, { true, "c", -1, 3, "rw" } };
static struct rule rules_type_a[] = { { true, "a", 60, -1, "rw" }, { false, "a", 60, 3, "w" }, { true, "a", -1, 7, "m" } };
static struct rule rules_deny_subsets[] = { { true, "a", -1, -1, "rwm" }, { false, "c", 61, -1, "w" }, { false, "b", -1, -1, "rm" }, { false, "c", 63, 7, "" } };
static struct rule rules_access_subsets[] = { { true, "c", 63, 7, "m" }, { true, "c", 63, -1, "wm" }, { false, "c", -1, 7, "r" }, { true, "b", 62, 3, "rw" }, { true, "c", 121, -1, "rm" } };

#  define SCENARIO(N, R) { N, R, sizeof (R) / sizeof ((R)[0]) }

static struct scenario scenarios[] = {
  { "defaults-only", NULL, 0 },
  SCENARIO ("deny-all", rules_deny_all),
  SCENARIO ("deny-all-allow-null", rules_deny_all_allow_null),
  SCENARIO ("allow-major", rules_allow_major),
  SCENARIO ("allow-all-char", rules_allow_all_char),
  SCENARIO ("allow-all", rules_allow_all),
  SCENARIO ("partial-deny", rules_partial_deny),
  SCENARIO ("order", rules_order),
  SCENARIO ("deny-then-allow", rules_deny_then_allow),
  SCENARIO ("empty-access", rules_empty_access),
  SCENARIO ("any-major", rules_any_major),
  SCENARIO ("allow-all-shadows", rules_allow_all_shadows),
  SCENARIO ("any-minor", rules_any_minor),
  SCENARIO ("type-a", rules_type_a),
  SCENARIO ("deny-subsets", rules_deny_subsets),
  SCENARIO ("access-subsets", rules_access_subsets),
};

#  define N_SCENARIOS (sizeof (scenarios) / sizeof (scenarios[0]))

/* The majors reserved for local or experimental use, so that no device with a driver is opened.  */
static const int majors[] = { 60, 61, 62, 63, 120, 121, 122 };
static const int minors[] = { 0, 1, 2, 3, 5, 7, 8, 9, 200, 255 };

/* The devices are created here, and /tmp could be mounted nodev.  */
#  define NODES_DIR "/var/tmp"

static runtime_spec_schema_defs_linux_device_cgroup **
build_devs (struct rule *rules, size_t n)
{
  runtime_spec_schema_defs_linux_device_cgroup **devs, *store;
  size_t i;

  devs = calloc (n + 1, sizeof (*devs));
  store = calloc (n + 1, sizeof (*store));
  if (devs == NULL || store == NULL)
    abort ();

  for (i = 0; i < n; i++)
    {
      devs[i] = &store[i];
      store[i].allow = rules[i].allow;
      store[i].allow_present = 1;
      store[i].type = (char *) rules[i].type;
      store[i].access = (char *) rules[i].access;
      if (rules[i].major >= 0)
        {
          store[i].major = rules[i].major;
          store[i].major_present = 1;
        }
      if (rules[i].minor >= 0)
        {
          store[i].minor = rules[i].minor;
          store[i].minor_present = 1;
        }
    }
  return devs;
}

static void
free_devs (runtime_spec_schema_defs_linux_device_cgroup **devs)
{
  free (devs[0]);
  free (devs);
}

static bool
is_real_root ()
{
  unsigned long first, parent, count;
  FILE *f;
  int n;

  if (geteuid () != 0)
    return false;

  f = fopen ("/proc/self/uid_map", "re");
  if (f == NULL)
    return false;

  n = fscanf (f, "%lu %lu %lu", &first, &parent, &count);
  fclose (f);

  return n == 3 && first == 0 && parent == 0 && count == 4294967295UL;
}

static bool
can_run ()
{
  struct statfs sfs;

  if (! is_real_root ())
    return false;

  if (statfs (CGROUP_ROOT, &sfs) < 0 || sfs.f_type != CGROUP2_SUPER_MAGIC)
    return false;

  return true;
}

/* The program needs the bounded loops, supported since Linux 5.3.  On a newer kernel not being able to
   load it is an error.  */
static bool
kernel_supports_loops ()
{
  struct utsname u;
  int major, minor;

  if (uname (&u) < 0 || sscanf (u.release, "%d.%d", &major, &minor) != 2)
    return false;

  return major > 5 || (major == 5 && minor >= 3);
}

/* Return 1 if the cgroup denies the access, 0 if it is allowed, and -1 on an error.  */
static int
probe (int cgroup_fd, char type, int major, int minor, int what)
{
  libcrun_error_t err = NULL;
  char node[256], buf[32];
  mode_t mode = (type == 'b' ? S_IFBLK : S_IFCHR) | 0600;
  int pipefd[2], status;
  pid_t pid;

  snprintf (node, sizeof (node), NODES_DIR "/tests-ebpf-devices-%d-%c-%d-%d", getpid (), type, major, minor);

  /* what: 0 read, 1 write, 2 mknod, 3 read and write.  */
  if (what != 2)
    {
      unlink (node);
      if (mknod (node, mode, makedev (major, minor)) < 0)
        return -1;
    }

  if (pipe (pipefd) < 0)
    goto fail;

  pid = fork ();
  if (pid < 0)
    {
      close (pipefd[0]);
      close (pipefd[1]);
      goto fail;
    }

  if (pid == 0)
    {
      char c;
      int fd, res;

      close (pipefd[1]);
      if (read (pipefd[0], &c, 1) != 1)
        _exit (3);

      if (what == 2)
        {
          res = mknod (node, mode, makedev (major, minor));
          if (res == 0)
            {
              unlink (node);
              _exit (0);
            }
          _exit (errno == EPERM ? 1 : 2);
        }

      /* There is no driver for these majors, so an open that is allowed fails with ENXIO.  */
      fd = open (node, what == 0 ? O_RDONLY : what == 1 ? O_WRONLY
                                                        : O_RDWR);
      if (fd >= 0)
        {
          close (fd);
          _exit (0);
        }
      if (errno == ENXIO || errno == ENODEV)
        _exit (0);
      _exit (errno == EPERM ? 1 : 2);
    }

  close (pipefd[0]);

  snprintf (buf, sizeof (buf), "%d", pid);
  if (write_cgroup_file (cgroup_fd, "cgroup.procs", buf, strlen (buf), &err) < 0 || write (pipefd[1], "x", 1) != 1)
    {
      crun_error_release (&err);
      close (pipefd[1]);
      kill (pid, SIGKILL);
      waitpid (pid, &status, 0);
      goto fail;
    }
  close (pipefd[1]);

  waitpid (pid, &status, 0);
  unlink (node);

  if (! WIFEXITED (status) || WEXITSTATUS (status) > 1)
    return -1;

  return WEXITSTATUS (status);

fail:
  unlink (node);
  return -1;
}

static int
remove_cgroup (const char *path)
{
  if (path[0] == '\0' || rmdir (path) == 0 || errno == ENOENT)
    return 0;

  fprintf (stderr, "# cannot remove `%s`: %s\n", path, strerror (errno));
  return -1;
}

static int
make_cgroup (const char *name, char *path, size_t path_size)
{
  snprintf (path, path_size, CGROUP_ROOT "/%s-%d", name, getpid ());
  rmdir (path);
  if (mkdir (path, 0755) < 0)
    return -1;
  return open (path, O_DIRECTORY | O_RDONLY);
}

/* Compare the filter generated by create_dev_bpf with the one that reads the rules from a map.  The map
   is first created with the rules INITIAL and then updated to FINAL.  */
static int
compare_filters (struct scenario *initial, struct scenario *final, int *denied_out)
{
  runtime_spec_schema_defs_linux_device_cgroup **devs_initial = NULL, **devs_final = NULL;
  char path_legacy[256], path_map[256];
  int dir_legacy = -1, dir_map = -1;
  libcrun_error_t err = NULL;
  struct bpf_program *program = NULL;
  uint32_t *progs = NULL;
  size_t n_progs = 0;
  int ret, result = -1;
  int denied = 0;
  size_t a, b;
  int t, w;

  devs_initial = build_devs (initial->rules, initial->n);
  devs_final = build_devs (final->rules, final->n);

  dir_legacy = make_cgroup ("tests-ebpf-devices-legacy", path_legacy, sizeof (path_legacy));
  dir_map = make_cgroup ("tests-ebpf-devices-map", path_map, sizeof (path_map));
  if (dir_legacy < 0 || dir_map < 0)
    goto exit;

  program = create_dev_bpf (devs_final, final->n, &err);
  if (program == NULL)
    goto exit;

  ret = libcrun_ebpf_load (program, dir_legacy, NULL, &err);
  if (ret < 0)
    goto exit;

  ret = libcrun_ebpf_devices_set (devs_initial, initial->n, dir_map, &err);
  if (ret == 0 && initial != final)
    ret = libcrun_ebpf_devices_update (devs_final, final->n, dir_map, &err);
  if (ret != 0)
    {
      /* The kernel does not support the program.  */
      result = ret > 0 && ! kernel_supports_loops () ? 77 : -1;
      goto exit;
    }

  /* The update must replace the rules and not add a second program.  */
  ret = libcrun_ebpf_query_cgroup_progs (path_map, &progs, &n_progs, &err);
  if (ret < 0 || n_progs != 1)
    goto exit;

  result = 0;
  for (t = 0; t < 2; t++)
    for (a = 0; a < sizeof (majors) / sizeof (*majors); a++)
      for (b = 0; b < sizeof (minors) / sizeof (*minors); b++)
        for (w = 0; w < 4; w++)
          {
            char type = t ? 'b' : 'c';
            int r_legacy = probe (dir_legacy, type, majors[a], minors[b], w);
            int r_map = probe (dir_map, type, majors[a], minors[b], w);

            if (r_legacy < 0 || r_map < 0)
              {
                result = -1;
                goto exit;
              }

            denied += r_legacy;
            if (r_legacy != r_map)
              {
                fprintf (stderr, "# %s -> %s: %c %d:%d %s: legacy=%s map=%s\n", initial->name, final->name, type,
                         majors[a], minors[b], w == 0 ? "read" : w == 1 ? "write"
                                                             : w == 2   ? "mknod"
                                                                        : "read-write",
                         r_legacy ? "deny" : "allow", r_map ? "deny" : "allow");
                result = -1;
              }
          }

exit:
  if (result < 0 && err)
    fprintf (stderr, "# %s -> %s: %s\n", initial->name, final->name, err->msg);
  crun_error_release (&err);
  free (progs);
  free (program);
  if (dir_legacy >= 0)
    close (dir_legacy);
  if (dir_map >= 0)
    close (dir_map);
  if (remove_cgroup (path_legacy) < 0 || remove_cgroup (path_map) < 0)
    result = -1;
  free_devs (devs_initial);
  free_devs (devs_final);
  if (denied_out)
    *denied_out = denied;
  return result;
}

static int
test_same_rules ()
{
  size_t i;
  int denied;

  if (! can_run ())
    return 77;

  /* If nothing is denied the probes are not effective, e.g. NODES_DIR is mounted nodev.  */
  if (compare_filters (&scenarios[1], &scenarios[1], &denied) == 0 && denied == 0)
    return 77;

  for (i = 0; i < N_SCENARIOS; i++)
    {
      int ret = compare_filters (&scenarios[i], &scenarios[i], NULL);

      if (ret != 0)
        return ret;
    }
  return 0;
}

static int
test_update_rules ()
{
  size_t i;

  if (! can_run ())
    return 77;

  for (i = 0; i < N_SCENARIOS; i++)
    {
      int ret = compare_filters (&scenarios[i], &scenarios[(i + 5) % N_SCENARIOS], NULL);

      if (ret != 0)
        return ret;
    }
  return 0;
}

static runtime_spec_schema_defs_linux_device_cgroup **
build_many_devs (size_t n)
{
  runtime_spec_schema_defs_linux_device_cgroup **devs;
  struct rule *rules;
  size_t i;

  rules = calloc (n + 1, sizeof (*rules));
  if (rules == NULL)
    abort ();

  for (i = 0; i < n; i++)
    rules[i] = (struct rule) { true, "c", 100 + i, -1, "rw" };

  devs = build_devs (rules, n);
  free (rules);
  return devs;
}

static size_t
count_default_devices ()
{
  struct default_dev_s *default_devices = get_default_devices ();
  size_t n;

  for (n = 0; default_devices[n].type; n++)
    ;
  return n;
}

/* The table holds at most CRUN_DEV_MAX_RULES rules, including the default devices, and a longer list is an error.  */
static int
test_too_many_rules ()
{
  runtime_spec_schema_defs_linux_device_cgroup **devs_max, **devs_over;
  size_t n_max = CRUN_DEV_MAX_RULES - count_default_devices ();
  libcrun_error_t err = NULL;
  char *pin = NULL;
  uint32_t *progs = NULL;
  size_t n_progs = 0;
  char path[256];
  int dir, ret, result = -1;

  if (! can_run ())
    return 77;

  devs_max = build_many_devs (n_max);
  devs_over = build_many_devs (n_max + 1);

  dir = make_cgroup ("tests-ebpf-devices-max", path, sizeof (path));
  if (dir < 0)
    goto exit;

  ret = libcrun_ebpf_devices_set (devs_over, n_max + 1, dir, &err);
  if (ret >= 0 || crun_error_get_errno (&err) != E2BIG)
    goto exit;
  crun_error_release (&err);

  /* Nothing is attached when the rules do not fit.  */
  ret = libcrun_ebpf_query_cgroup_progs (path, &progs, &n_progs, &err);
  if (ret < 0 || n_progs != 0)
    goto exit;

  ret = libcrun_ebpf_devices_pin (devs_over, n_max + 1, &pin, &err);
  if (ret >= 0 || crun_error_get_errno (&err) != E2BIG)
    goto exit;
  crun_error_release (&err);

  ret = libcrun_ebpf_devices_set (devs_max, n_max, dir, &err);
  if (ret != 0)
    {
      /* The kernel does not support the program.  */
      result = ret > 0 && ! kernel_supports_loops () ? 77 : -1;
      goto exit;
    }

  ret = libcrun_ebpf_devices_update (devs_over, n_max + 1, dir, &err);
  if (ret >= 0 || crun_error_get_errno (&err) != E2BIG)
    goto exit;
  crun_error_release (&err);

  ret = libcrun_ebpf_devices_update (devs_max, n_max, dir, &err);
  if (ret != 0)
    goto exit;

  /* The first rule is the last record of the table, and a device that no rule matches is checked against every record.  */
  if (probe (dir, 'c', 100, 0, 0) != 0 || probe (dir, 'c', 100, 0, 1) != 0 || probe (dir, 'c', 60, 0, 0) != 1)
    {
      fprintf (stderr, "# test_too_many_rules: wrong access with a full table\n");
      goto exit;
    }

  result = 0;

exit:
  if (result < 0 && err)
    fprintf (stderr, "# test_too_many_rules: %s\n", err->msg);
  crun_error_release (&err);
  free (pin);
  free (progs);
  if (dir >= 0)
    close (dir);
  if (remove_cgroup (path) < 0)
    result = -1;
  free_devs (devs_max);
  free_devs (devs_over);
  return result;
}

/* Updating requires that the program reads its rules from a map, otherwise 1 is returned.  A program that is already
   attached, e.g. by an older version, is not replaced by the one that reads its rules from a map.  */
static int
test_update_without_map ()
{
  runtime_spec_schema_defs_linux_device_cgroup **devs;
  uint32_t *progs = NULL, *progs_after = NULL;
  size_t n_progs = 0, n_progs_after = 0;
  struct bpf_program *program;
  libcrun_error_t err = NULL;
  char path[256];
  int dir, ret;

  if (! can_run ())
    return 77;

  dir = make_cgroup ("tests-ebpf-devices-nomap", path, sizeof (path));
  if (dir < 0)
    return -1;

  devs = build_devs (scenarios[1].rules, scenarios[1].n);

  /* No program at all.  */
  ret = libcrun_ebpf_devices_update (devs, scenarios[1].n, dir, &err);
  crun_error_release (&err);
  if (ret != 1)
    goto fail;

  /* A program generated from the rules.  */
  program = create_dev_bpf (devs, scenarios[1].n, &err);
  if (program == NULL)
    goto fail;
  ret = libcrun_ebpf_load (program, dir, NULL, &err);
  free (program);
  if (ret < 0)
    goto fail;

  ret = libcrun_ebpf_devices_update (devs, scenarios[1].n, dir, &err);
  crun_error_release (&err);
  if (ret != 1)
    goto fail;

  ret = libcrun_ebpf_query_cgroup_progs (path, &progs, &n_progs, &err);
  if (ret < 0 || n_progs != 1)
    goto fail;

  ret = libcrun_ebpf_devices_set (devs, scenarios[1].n, dir, &err);
  if (ret != 1)
    goto fail;

  ret = libcrun_ebpf_query_cgroup_progs (path, &progs_after, &n_progs_after, &err);
  if (ret < 0 || n_progs_after != 1 || progs_after[0] != progs[0])
    goto fail;

  free (progs);
  free (progs_after);
  free_devs (devs);
  close (dir);
  return remove_cgroup (path);

fail:
  if (err)
    fprintf (stderr, "# test_update_without_map: %s\n", err->msg);
  crun_error_release (&err);
  free (progs);
  free (progs_after);
  free_devs (devs);
  close (dir);
  remove_cgroup (path);
  return -1;
}

/* If the rules cannot be written, the program that would deny every device must not stay attached.  The write is made
   to fail with a seccomp filter.  */
static int
test_write_failure ()
{
  runtime_spec_schema_defs_linux_device_cgroup **devs;
  libcrun_error_t err = NULL;
  uint32_t *progs = NULL;
  size_t n_progs = 0;
  int dir, ret, status, result = -1;
  char path[256];
  pid_t pid;

  if (! can_run ())
    return 77;

  dir = make_cgroup ("tests-ebpf-devices-wfail", path, sizeof (path));
  if (dir < 0)
    return -1;

  devs = build_devs (scenarios[2].rules, scenarios[2].n);

  pid = fork ();
  if (pid < 0)
    goto exit;

  if (pid == 0)
    {
      struct sock_filter filter[] = {
        BPF_STMT (BPF_LD | BPF_W | BPF_ABS, offsetof (struct seccomp_data, nr)),
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf, 0, 3),
        BPF_STMT (BPF_LD | BPF_W | BPF_ABS,
                  offsetof (struct seccomp_data, args[0]) + (__BYTE_ORDER == __BIG_ENDIAN ? 4 : 0)),
        BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, BPF_MAP_UPDATE_ELEM, 0, 1),
        BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOMEM),
        BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      };
      struct sock_fprog fprog = { .len = sizeof (filter) / sizeof (filter[0]), .filter = filter };

      if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 || prctl (PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog) < 0)
        _exit (2);

      ret = libcrun_ebpf_devices_set (devs, scenarios[2].n, dir, &err);
      if (ret == 1)
        _exit (77);
      _exit (ret < 0 && crun_error_get_errno (&err) == ENOMEM ? 0 : 1);
    }

  if (waitpid (pid, &status, 0) < 0 || ! WIFEXITED (status))
    goto exit;

  if (WEXITSTATUS (status) == 77)
    {
      /* The kernel does not support the program.  */
      result = kernel_supports_loops () ? -1 : 77;
      goto exit;
    }
  if (WEXITSTATUS (status) != 0)
    goto exit;

  ret = libcrun_ebpf_query_cgroup_progs (path, &progs, &n_progs, &err);
  if (ret < 0 || n_progs != 0)
    goto exit;

  result = 0;

exit:
  if (result < 0 && err)
    fprintf (stderr, "# test_write_failure: %s\n", err->msg);
  crun_error_release (&err);
  free (progs);
  free_devs (devs);
  close (dir);
  if (remove_cgroup (path) < 0)
    result = -1;
  return result;
}

/* The same pinned program is attached to two cgroups, each of them with its own rules.  */
static int
test_shared_program ()
{
  runtime_spec_schema_defs_linux_device_cgroup **devs_deny, **devs_allow;
  char *pin = NULL, *pin_again = NULL;
  libcrun_error_t err = NULL;
  char path_a[256], path_b[256];
  int dir_a = -1, dir_b = -1, prog_fd = -1;
  union bpf_attr attr;
  int ret, result = -1;
  int denied_a, denied_b;

  if (! can_run ())
    return 77;

  path_a[0] = path_b[0] = '\0';
  devs_deny = build_devs (scenarios[1].rules, scenarios[1].n);
  devs_allow = build_devs (scenarios[5].rules, scenarios[5].n);

  ret = libcrun_ebpf_devices_pin (devs_deny, scenarios[1].n, &pin, &err);
  if (ret != 0)
    {
      /* Without the BPF file system or the program there is nothing to test.  */
      result = ret > 0 || (err && crun_error_get_errno (&err) == ENOENT) ? 77 : -1;
      goto exit;
    }

  /* A second request uses the same program.  */
  ret = libcrun_ebpf_devices_pin (devs_allow, scenarios[5].n, &pin_again, &err);
  if (ret != 0 || strcmp (pin, pin_again) != 0)
    goto exit;

  memset (&attr, 0, sizeof (attr));
  attr.pathname = (uint64_t) (unsigned long) pin;
  prog_fd = syscall (__NR_bpf, BPF_OBJ_GET, &attr, sizeof (attr));
  if (prog_fd < 0)
    goto exit;

  dir_a = make_cgroup ("tests-ebpf-devices-shared-a", path_a, sizeof (path_a));
  dir_b = make_cgroup ("tests-ebpf-devices-shared-b", path_b, sizeof (path_b));
  if (dir_a < 0 || dir_b < 0)
    goto exit;

  /* As systemd does with BPFProgram=.  */
  for (int i = 0; i < 2; i++)
    {
      memset (&attr, 0, sizeof (attr));
      attr.target_fd = i == 0 ? dir_a : dir_b;
      attr.attach_bpf_fd = prog_fd;
      attr.attach_type = BPF_CGROUP_DEVICE;
      attr.attach_flags = BPF_F_ALLOW_MULTI;
      if (syscall (__NR_bpf, BPF_PROG_ATTACH, &attr, sizeof (attr)) < 0)
        goto exit;
    }

  if (libcrun_ebpf_devices_update (devs_deny, scenarios[1].n, dir_a, &err) != 0
      || libcrun_ebpf_devices_update (devs_allow, scenarios[5].n, dir_b, &err) != 0)
    goto exit;

  /* A device that is not one of the default ones.  */
  denied_a = probe (dir_a, 'c', 63, 7, 0);
  denied_b = probe (dir_b, 'c', 63, 7, 0);
  if (denied_a == 1 && denied_b == 0)
    result = 0;

exit:
  if (result < 0 && err)
    fprintf (stderr, "# test_shared_program: %s\n", err->msg);
  crun_error_release (&err);
  if (prog_fd >= 0)
    close (prog_fd);
  if (dir_a >= 0)
    close (dir_a);
  if (dir_b >= 0)
    close (dir_b);
  if (remove_cgroup (path_a) < 0 || remove_cgroup (path_b) < 0)
    result = -1;
  /* The pinned program is shared by the other containers, so it must not be removed.  */
  free (pin);
  free (pin_again);
  free_devs (devs_deny);
  free_devs (devs_allow);
  return result;
}

static int
add_rule (int dir, bool allow, int major, int minor, const char *access, libcrun_error_t *err)
{
  struct rule r = { allow, "c", major, minor, access };
  runtime_spec_schema_defs_linux_device_cgroup **devs = build_devs (&r, 1);
  int ret;

  ret = libcrun_ebpf_devices_add (devs, 1, dir, err);
  free_devs (devs);
  return ret;
}

/* Adding a rule requires that the program reads its rules from a map, otherwise 1 is returned.  */
static int
test_add_without_map ()
{
  runtime_spec_schema_defs_linux_device_cgroup **devs;
  struct bpf_program *program;
  libcrun_error_t err = NULL;
  char path[256];
  int dir, ret, result = -1;

  if (! can_run ())
    return 77;

  dir = make_cgroup ("tests-ebpf-devices-add-nomap", path, sizeof (path));
  if (dir < 0)
    return -1;

  devs = build_devs (scenarios[1].rules, scenarios[1].n);

  /* No program at all.  */
  ret = add_rule (dir, true, 63, 7, "rwm", &err);
  if (ret != 1)
    goto exit;

  /* A program generated from the rules.  */
  program = create_dev_bpf (devs, scenarios[1].n, &err);
  if (program == NULL)
    goto exit;
  ret = libcrun_ebpf_load (program, dir, NULL, &err);
  free (program);
  if (ret < 0)
    goto exit;

  ret = add_rule (dir, true, 63, 7, "rwm", &err);
  if (ret != 1)
    goto exit;

  /* The generated program is still in place.  */
  if (probe (dir, 'c', 63, 7, 0) != 1)
    goto exit;

  result = 0;

exit:
  if (result < 0 && err)
    fprintf (stderr, "# test_add_without_map: %s\n", err->msg);
  crun_error_release (&err);
  free_devs (devs);
  close (dir);
  if (remove_cgroup (path) < 0)
    result = -1;
  return result;
}

/* A rule that is added has a higher priority than the rules already there, and adding it again changes nothing.  */
static int
test_add_rules ()
{
  static struct rule rules_deny[] = { { false, "a", -1, -1, "rwm" }, { false, "c", 63, 7, "rwm" } };
  static struct rule rules_last_wins[] = { { false, "c", 63, 8, "r" }, { true, "c", 63, 8, "r" } };
  runtime_spec_schema_defs_linux_device_cgroup **devs, **devs_last_wins;
  libcrun_error_t err = NULL;
  uint32_t *progs = NULL;
  size_t n_progs = 0;
  char path[256];
  int dir, ret, result = -1;

  if (! can_run ())
    return 77;

  dir = make_cgroup ("tests-ebpf-devices-add", path, sizeof (path));
  if (dir < 0)
    return -1;

  devs = build_devs (rules_deny, 2);
  devs_last_wins = build_devs (rules_last_wins, 2);

  ret = libcrun_ebpf_devices_set (devs, 2, dir, &err);
  if (ret != 0)
    {
      /* The kernel does not support the program.  */
      result = ret > 0 && ! kernel_supports_loops () ? 77 : -1;
      goto exit;
    }

  if (probe (dir, 'c', 63, 7, 0) != 1)
    goto exit;

  /* The rule is not shadowed by the deny rules that are already in the list.  */
  ret = add_rule (dir, true, 63, 7, "r", &err);
  if (ret != 0)
    goto exit;

  if (probe (dir, 'c', 63, 7, 0) != 0 || probe (dir, 'c', 63, 7, 1) != 1 || probe (dir, 'c', 63, 8, 0) != 1
      || probe (dir, 'c', 60, 3, 0) != 1 || probe (dir, 'b', 63, 7, 0) != 1)
    goto exit;

  /* The same rule again.  */
  ret = add_rule (dir, true, 63, 7, "r", &err);
  if (ret != 0 || probe (dir, 'c', 63, 7, 0) != 0)
    goto exit;

  /* A deny rule has a higher priority than the allow rule, and the allow rule added again is moved in front.  */
  ret = add_rule (dir, false, 63, 7, "rwm", &err);
  if (ret != 0 || probe (dir, 'c', 63, 7, 0) != 1)
    goto exit;

  ret = add_rule (dir, true, 63, 7, "r", &err);
  if (ret != 0 || probe (dir, 'c', 63, 7, 0) != 0)
    goto exit;

  /* The last rule of a single call has the highest priority.  */
  ret = libcrun_ebpf_devices_add (devs_last_wins, 2, dir, &err);
  if (ret != 0 || probe (dir, 'c', 63, 8, 0) != 0 || probe (dir, 'c', 63, 7, 0) != 0)
    goto exit;

  /* The rules are replaced in the map and no other program is attached.  */
  ret = libcrun_ebpf_query_cgroup_progs (path, &progs, &n_progs, &err);
  if (ret < 0 || n_progs != 1)
    goto exit;

  result = 0;

exit:
  if (result < 0 && err)
    fprintf (stderr, "# test_add_rules: %s\n", err->msg);
  crun_error_release (&err);
  free (progs);
  free_devs (devs);
  free_devs (devs_last_wins);
  close (dir);
  if (remove_cgroup (path) < 0)
    result = -1;
  return result;
}

/* The table holds at most CRUN_DEV_MAX_RULES rules, a rule that is already there does not use another one.  */
static int
test_add_too_many_rules ()
{
  size_t n = CRUN_DEV_MAX_RULES - count_default_devices () - 1;
  runtime_spec_schema_defs_linux_device_cgroup **devs;
  libcrun_error_t err = NULL;
  char path[256];
  int dir, ret, result = -1;

  if (! can_run ())
    return 77;

  dir = make_cgroup ("tests-ebpf-devices-add-max", path, sizeof (path));
  if (dir < 0)
    return -1;

  /* One rule less than the maximum, none of them matches the devices that are probed.  */
  devs = build_many_devs (n);

  ret = libcrun_ebpf_devices_set (devs, n, dir, &err);
  if (ret != 0)
    {
      /* The kernel does not support the program.  */
      result = ret > 0 && ! kernel_supports_loops () ? 77 : -1;
      goto exit;
    }

  ret = add_rule (dir, true, 63, 7, "rwm", &err);
  if (ret != 0)
    goto exit;

  ret = add_rule (dir, true, 63, 7, "rwm", &err);
  if (ret != 0)
    goto exit;

  ret = add_rule (dir, true, 63, 8, "rwm", &err);
  if (ret >= 0 || crun_error_get_errno (&err) != E2BIG)
    goto exit;
  crun_error_release (&err);

  /* The previous rules are still in place.  */
  if (probe (dir, 'c', 63, 7, 0) != 0 || probe (dir, 'c', 63, 8, 0) != 1)
    goto exit;

  result = 0;

exit:
  if (result < 0 && err)
    fprintf (stderr, "# test_add_too_many_rules: %s\n", err->msg);
  crun_error_release (&err);
  free_devs (devs);
  close (dir);
  if (remove_cgroup (path) < 0)
    result = -1;
  return result;
}

#else

static int
skip_test ()
{
  return 77;
}

#  define test_same_rules skip_test
#  define test_update_rules skip_test
#  define test_too_many_rules skip_test
#  define test_update_without_map skip_test
#  define test_write_failure skip_test
#  define test_shared_program skip_test
#  define test_add_without_map skip_test
#  define test_add_rules skip_test
#  define test_add_too_many_rules skip_test

#endif

int
main ()
{
  RUN_TEST (test_same_rules);
  RUN_TEST (test_update_rules);
  RUN_TEST (test_too_many_rules);
  RUN_TEST (test_update_without_map);
  RUN_TEST (test_write_failure);
  RUN_TEST (test_shared_program);
  RUN_TEST (test_add_without_map);
  RUN_TEST (test_add_rules);
  RUN_TEST (test_add_too_many_rules);
  print_tap_plan ();
  return 0;
}
