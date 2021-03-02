/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>
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

#include <libcrun/error.h>
#include <libcrun/cgroup.h>
#include <libcrun/utils.h>
#include <libcrun/status.h>
#include <libcrun/seccomp.h>
#include <libcrun/ebpf.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>

static int test_mode = -1;

static char *
make_nul_terminated (uint8_t *buf, size_t len)
{
  char *r;

  r = malloc (len + 1);
  if (r == NULL)
    return 0;
  memcpy (r, buf, len);
  r[len] = '\0';

  return r;
}

static int
test_generate_ebpf (uint8_t *buf, size_t len)
{
  libcrun_error_t err = NULL;
  cleanup_free struct bpf_program *program = NULL;
  cleanup_free char *copy = NULL;
  struct bpf_program *new_program;
  cleanup_close int fd = -1;
  char access[4];

  copy = make_nul_terminated (buf, len);
  if (copy == NULL)
    return 0;

  program = bpf_program_new (2048);

  bpf_program_init_dev (program, &err);
  crun_error_release (&err);

  new_program = bpf_program_append (program, copy, len / 2);
  if (new_program == NULL)
    return 0;
  program = new_program;

  if (len < 10)
    return 0;

  memcpy (access, buf, 3);
  access[3] = '\0';

  new_program = bpf_program_append_dev (program, access, copy[3], copy[4], copy[5], copy[6] & 0x1, &err);
  if (new_program == NULL)
    {
      crun_error_release (&err);
      return 0;
    }
  program = new_program;

  new_program = bpf_program_init_dev (program, &err);
  if (new_program == NULL)
    {
      crun_error_release (&err);
      return 0;
    }
  program = new_program;

  fd = open ("/dev/null", O_WRONLY);
  if (fd < 0)
    return 0;

  libcrun_ebpf_load (program, fd, NULL, &err);
  crun_error_release (&err);
  return 0;
}

char *chroot_realpath (const char *chroot, const char *path, char resolved_path[]);

static int
test_chroot_realpath (uint8_t *buf, size_t len)
{
  cleanup_free char *path;
  char resolved_path[PATH_MAX];

  path = make_nul_terminated (buf, len);
  if (path == NULL)
    return 0;

  chroot_realpath (".", path, resolved_path);
  (void) resolved_path;
  return 0;
}

static int
test_libcrun_str2sig (uint8_t *buf, size_t len)
{
  cleanup_free char *name;

  name = make_nul_terminated (buf, len);
  if (name == NULL)
    return 0;

  libcrun_str2sig (name);
  return 0;
}

static int
generate_seccomp (uint8_t *buf, size_t len)
{
  libcrun_error_t err = NULL;
  cleanup_container libcrun_container_t *container = NULL;
  cleanup_free char *conf = NULL;
  cleanup_close int outfd = -1;

  conf = make_nul_terminated (buf, len);
  if (conf == NULL)
    return 0;

  container = libcrun_container_load_from_memory (conf, &err);
  if (container == NULL)
    {
      crun_error_release (&err);
      return 0;
    }

  outfd = open ("/dev/null", O_WRONLY);
  if (outfd < 0)
    return 0;

  libcrun_generate_seccomp (container, outfd, 0, &err);
  crun_error_release (&err);
  return 0;
}

static int
test_read_cgroup_pids (uint8_t *buf, size_t len)
{
  cleanup_free pid_t *pids = NULL;
  cleanup_free char *path = NULL;
  libcrun_error_t err = NULL;

  path = make_nul_terminated (buf, len);
  if (path == NULL)
    return 0;

  libcrun_cgroup_read_pids (path, true, &pids, &err);
  crun_error_release (&err);
  return 0;
}

static int
run_one_container (uint8_t *buf, size_t len, bool detach)
{
  cleanup_free char *conf = NULL;
  const char *container_status = NULL;
  cleanup_container libcrun_container_t *container = NULL;
  libcrun_context_t ctx;
  char id[64];
  static unsigned long long counter = 0;
  libcrun_error_t err = NULL;
  libcrun_container_status_t status;
  int running;

  conf = make_nul_terminated (buf, len);
  if (conf == NULL)
    return 0;

  container = libcrun_container_load_from_memory (conf, &err);
  if (container == NULL)
    {
      crun_error_release (&err);
      return 0;
    }

  memset (&ctx, 0, sizeof (ctx));
  sprintf (id, "fuzzer-%d-%llu", getpid (), counter++);
  ctx.id = id;
  ctx.bundle = "rootfs";
  ctx.detach = detach;
  ctx.config_file_content = conf;

  libcrun_container_run (&ctx, container, 0, &err);
  crun_error_release (&err);

  memset (&status, 0, sizeof (status));

  libcrun_read_container_status (&status, NULL, id, &err);
  crun_error_release (&err);

  libcrun_get_container_state_string (id, &status, NULL, &container_status, &running, &err);
  crun_error_release (&err);

  libcrun_free_container_status (&status);

  libcrun_container_delete (&ctx, container->container_def, id, true, &err);
  crun_error_release (&err);
  return 0;
}

static int
run_one_test (int mode, uint8_t *buf, size_t len)
{
  int i;

  switch (mode)
    {
    case 0:
      run_one_container (buf, len, false);
      break;

    case 1:
      run_one_container (buf, len, true);
      break;

    case 2:
      generate_seccomp (buf, len);
      break;

    case 3:
      test_libcrun_str2sig (buf, len);
      break;

    case 4:
      test_chroot_realpath (buf, len);
      break;

    case 5:
      test_generate_ebpf (buf, len);
      break;

    case 6:
      test_read_cgroup_pids (buf, len);
      break;

      /* ALL mode.  */
    case -1:
      for (i = 0; i <= 6; i++)
        run_one_test (i, buf, len);
      break;

    default:
      fprintf (stderr, "invalid mode %d\n", mode);
      raise (SIGABRT);
      break;
    }
  return 0;
}

int
LLVMFuzzerInitialize (int *argc arg_unused, char ***argv arg_unused)
{
  return 0;
}

int
LLVMFuzzerTestOneInput (uint8_t *buf, size_t len)
{
  run_one_test (test_mode, buf, len);
  return 0;
}

int
main (int argc, char **argv)
{
  const char *t = getenv ("FUZZING_MODE");
  if (t)
    test_mode = atoi (t);

  if (argc > 1)
    {
      libcrun_error_t err = NULL;
      cleanup_free uint8_t *content = NULL;
      size_t len;

      if (read_all_file (argv[1], (char **) &content, &len, &err) < 0)
        {
          libcrun_fail_with_error (err->status, "%s", err->msg);
            return -1;
        }
      return LLVMFuzzerTestOneInput (content, len);
    }
#ifdef FUZZER
  extern void HF_ITER (uint8_t** buf, size_t* len);
  for (;;)
    {
      size_t len;
      uint8_t *buf;

      HF_ITER (&buf, &len);

      LLVMFuzzerTestOneInput (buf, len);
    }
#endif
  return 0;
}
