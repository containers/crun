/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2026 Eugene Gvozdetsky <gvozdet@gmail.com>
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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/filter.h>

#include "utils.h"
#include "io_uring.h"

/* The policy is read from this annotation, in the shape proposed for
   `linux.ioUring` in opencontainers/runtime-spec#1328:

   {"ops": ["IORING_OP_READ", ...], "socketFamilies": ["AF_INET", ...]}

   `ops` are the allowed opcodes, every other opcode is denied.
   `socketFamilies`, when present, limits IORING_OP_SOCKET to these
   address families.  */
#define IO_URING_ANNOTATION "run.oci.io_uring"

/* Set for the process that checks the restrictions after exec, see
   check_restrictions_kept_on_exec.  */
#define IO_URING_EXEC_CHECK_ENV "_LIBCRUN_IO_URING_EXEC_CHECK"

/* From <linux/io_uring.h> and <linux/io_uring/bpf_filter.h>, Linux 7.0.  */
#define CRUN_IORING_REGISTER_RESTRICTIONS 11
#define CRUN_IORING_REGISTER_BPF_FILTER 37
#define CRUN_IO_URING_BPF_CMD_FILTER 1
/* Offset of the per-opcode data in struct io_uring_bpf_ctx.  For
   IORING_OP_SOCKET, the first word is the address family.  */
#define CRUN_IO_URING_BPF_CTX_PDU_OFFSET 16

struct crun_io_uring_bpf_filter
{
  uint32_t opcode;
  uint32_t flags;
  uint32_t filter_len;
  uint8_t pdu_size;
  uint8_t resv[3];
  uint64_t filter_ptr;
  uint64_t resv2[5];
};

struct crun_io_uring_bpf
{
  uint16_t cmd_type;
  uint16_t cmd_flags;
  uint32_t resv;
  struct crun_io_uring_bpf_filter filter;
};

/* The io_uring opcodes, in `enum io_uring_op` order.  */
static const char *io_uring_ops[] = {
  "IORING_OP_NOP",
  "IORING_OP_READV",
  "IORING_OP_WRITEV",
  "IORING_OP_FSYNC",
  "IORING_OP_READ_FIXED",
  "IORING_OP_WRITE_FIXED",
  "IORING_OP_POLL_ADD",
  "IORING_OP_POLL_REMOVE",
  "IORING_OP_SYNC_FILE_RANGE",
  "IORING_OP_SENDMSG",
  "IORING_OP_RECVMSG",
  "IORING_OP_TIMEOUT",
  "IORING_OP_TIMEOUT_REMOVE",
  "IORING_OP_ACCEPT",
  "IORING_OP_ASYNC_CANCEL",
  "IORING_OP_LINK_TIMEOUT",
  "IORING_OP_CONNECT",
  "IORING_OP_FALLOCATE",
  "IORING_OP_OPENAT",
  "IORING_OP_CLOSE",
  "IORING_OP_FILES_UPDATE",
  "IORING_OP_STATX",
  "IORING_OP_READ",
  "IORING_OP_WRITE",
  "IORING_OP_FADVISE",
  "IORING_OP_MADVISE",
  "IORING_OP_SEND",
  "IORING_OP_RECV",
  "IORING_OP_OPENAT2",
  "IORING_OP_EPOLL_CTL",
  "IORING_OP_SPLICE",
  "IORING_OP_PROVIDE_BUFFERS",
  "IORING_OP_REMOVE_BUFFERS",
  "IORING_OP_TEE",
  "IORING_OP_SHUTDOWN",
  "IORING_OP_RENAMEAT",
  "IORING_OP_UNLINKAT",
  "IORING_OP_MKDIRAT",
  "IORING_OP_SYMLINKAT",
  "IORING_OP_LINKAT",
  "IORING_OP_MSG_RING",
  "IORING_OP_FSETXATTR",
  "IORING_OP_SETXATTR",
  "IORING_OP_FGETXATTR",
  "IORING_OP_GETXATTR",
  "IORING_OP_SOCKET",
  "IORING_OP_URING_CMD",
  "IORING_OP_SEND_ZC",
  "IORING_OP_SENDMSG_ZC",
  "IORING_OP_READ_MULTISHOT",
  "IORING_OP_WAITID",
  "IORING_OP_FUTEX_WAIT",
  "IORING_OP_FUTEX_WAKE",
  "IORING_OP_FUTEX_WAITV",
  "IORING_OP_FIXED_FD_INSTALL",
  "IORING_OP_FTRUNCATE",
  "IORING_OP_BIND",
  "IORING_OP_LISTEN",
  "IORING_OP_RECV_ZC",
  "IORING_OP_EPOLL_WAIT",
  "IORING_OP_READV_FIXED",
  "IORING_OP_WRITEV_FIXED",
  "IORING_OP_PIPE",
  "IORING_OP_NOP128",
  "IORING_OP_URING_CMD128",
};

#define IO_URING_OPS_LEN (sizeof (io_uring_ops) / sizeof (io_uring_ops[0]))
#define IORING_OP_NOP_VALUE 0
#define IORING_OP_SOCKET_VALUE 45
/* The SQE opcode is 8 bits.  */
#define IO_URING_MAX_OPCODES 256

/* Only constants and layouts: the opcode table may be older or newer than
   the headers.  */
#ifdef HAVE_LINUX_IO_URING_BPF_FILTER_H
#  include <stddef.h>
#  include <linux/io_uring.h>
#  include <linux/io_uring/bpf_filter.h>

_Static_assert (CRUN_IORING_REGISTER_RESTRICTIONS == IORING_REGISTER_RESTRICTIONS, "IORING_REGISTER_RESTRICTIONS");
_Static_assert (CRUN_IORING_REGISTER_BPF_FILTER == IORING_REGISTER_BPF_FILTER, "IORING_REGISTER_BPF_FILTER");
_Static_assert (CRUN_IO_URING_BPF_CMD_FILTER == IO_URING_BPF_CMD_FILTER, "IO_URING_BPF_CMD_FILTER");
_Static_assert (CRUN_IO_URING_BPF_CTX_PDU_OFFSET == offsetof (struct io_uring_bpf_ctx, socket.family), "struct io_uring_bpf_ctx");
_Static_assert (sizeof (struct crun_io_uring_bpf) == sizeof (struct io_uring_bpf), "struct io_uring_bpf");
_Static_assert (offsetof (struct crun_io_uring_bpf, filter) == offsetof (struct io_uring_bpf, filter), "struct io_uring_bpf");
_Static_assert (sizeof (struct crun_io_uring_bpf_filter) == sizeof (struct io_uring_bpf_filter), "struct io_uring_bpf_filter");
_Static_assert (offsetof (struct crun_io_uring_bpf_filter, filter_len) == offsetof (struct io_uring_bpf_filter, filter_len),
                "struct io_uring_bpf_filter");
_Static_assert (offsetof (struct crun_io_uring_bpf_filter, filter_ptr) == offsetof (struct io_uring_bpf_filter, filter_ptr),
                "struct io_uring_bpf_filter");
_Static_assert (IORING_OP_NOP_VALUE == IORING_OP_NOP, "IORING_OP_NOP");
_Static_assert (IORING_OP_SOCKET_VALUE == IORING_OP_SOCKET, "IORING_OP_SOCKET");
#endif

/* From <linux/socket.h>, Linux 7.0: libc may lack the newer ones.  */
static const struct
{
  const char *name;
  int value;
} io_uring_socket_families[] = {
  { "AF_UNIX", 1 },
  { "AF_LOCAL", 1 },
  { "AF_INET", 2 },
  { "AF_AX25", 3 },
  { "AF_IPX", 4 },
  { "AF_APPLETALK", 5 },
  { "AF_NETROM", 6 },
  { "AF_BRIDGE", 7 },
  { "AF_ATMPVC", 8 },
  { "AF_X25", 9 },
  { "AF_INET6", 10 },
  { "AF_ROSE", 11 },
  { "AF_DECnet", 12 },
  { "AF_NETBEUI", 13 },
  { "AF_SECURITY", 14 },
  { "AF_KEY", 15 },
  { "AF_NETLINK", 16 },
  { "AF_ROUTE", 16 },
  { "AF_PACKET", 17 },
  { "AF_ASH", 18 },
  { "AF_ECONET", 19 },
  { "AF_ATMSVC", 20 },
  { "AF_RDS", 21 },
  { "AF_SNA", 22 },
  { "AF_IRDA", 23 },
  { "AF_PPPOX", 24 },
  { "AF_WANPIPE", 25 },
  { "AF_LLC", 26 },
  { "AF_IB", 27 },
  { "AF_MPLS", 28 },
  { "AF_CAN", 29 },
  { "AF_TIPC", 30 },
  { "AF_BLUETOOTH", 31 },
  { "AF_IUCV", 32 },
  { "AF_RXRPC", 33 },
  { "AF_ISDN", 34 },
  { "AF_PHONET", 35 },
  { "AF_IEEE802154", 36 },
  { "AF_CAIF", 37 },
  { "AF_ALG", 38 },
  { "AF_NFC", 39 },
  { "AF_VSOCK", 40 },
  { "AF_KCM", 41 },
  { "AF_QIPCRTR", 42 },
  { "AF_SMC", 43 },
  { "AF_XDP", 44 },
  { "AF_MCTP", 45 },
};

#define IO_URING_SOCKET_FAMILIES_LEN (sizeof (io_uring_socket_families) / sizeof (io_uring_socket_families[0]))

struct io_uring_policy_s
{
  bool ops[IO_URING_OPS_LEN];
  bool has_socket_families;
  uint32_t socket_families[IO_URING_SOCKET_FAMILIES_LEN];
  size_t socket_families_len;
};

static int
find_op (const char *name)
{
  size_t i;

  for (i = 0; i < IO_URING_OPS_LEN; i++)
    if (strcmp (io_uring_ops[i], name) == 0)
      return i;
  return -1;
}

static int
find_socket_family (const char *name)
{
  size_t i;

  for (i = 0; i < IO_URING_SOCKET_FAMILIES_LEN; i++)
    if (strcmp (io_uring_socket_families[i].name, name) == 0)
      return io_uring_socket_families[i].value;
  return -1;
}

static void
add_socket_family (struct io_uring_policy_s *policy, const char *name, bool warn)
{
  int family = find_socket_family (name);
  size_t i;

  /* Like an unknown operation, an unknown family stays denied.  */
  if (UNLIKELY (family < 0))
    {
      if (warn)
        libcrun_warning ("%s: unknown socket address family `%s` ignored", IO_URING_ANNOTATION, name);
      return;
    }

  for (i = 0; i < policy->socket_families_len; i++)
    if (policy->socket_families[i] == (uint32_t) family)
      return;

  policy->socket_families[policy->socket_families_len++] = family;
}

/* WARN is set only once per policy, as it is parsed again when applied.  */
static int
parse_policy (const char *annotation, struct io_uring_policy_s *policy, bool warn, libcrun_error_t *err)
{
  json_object *doc = NULL;
  json_object *ops = NULL;
  json_object *families = NULL;
  size_t i, len;
  int ret;

  memset (policy, 0, sizeof (*policy));

  ret = parse_json_file (&doc, annotation, NULL, err);
  if (UNLIKELY (ret < 0))
    return crun_error_wrap (err, "invalid %s annotation", IO_URING_ANNOTATION);

  if (UNLIKELY (! json_object_is_type (doc, json_type_object)))
    {
      ret = crun_make_error (err, 0, "%s: expected a JSON object", IO_URING_ANNOTATION);
      goto exit;
    }

  json_object_object_foreach (doc, key, val)
  {
    (void) val;
    if (strcmp (key, "ops") != 0 && strcmp (key, "socketFamilies") != 0)
      {
        ret = crun_make_error (err, 0, "%s: unknown property `%s`", IO_URING_ANNOTATION, key);
        goto exit;
      }
  }

  if (UNLIKELY (! json_object_object_get_ex (doc, "ops", &ops) || ! json_object_is_type (ops, json_type_array)))
    {
      ret = crun_make_error (err, 0, "%s: `ops` must be an array", IO_URING_ANNOTATION);
      goto exit;
    }

  len = json_object_array_length (ops);
  for (i = 0; i < len; i++)
    {
      json_object *op = json_object_array_get_idx (ops, i);
      const char *name;
      int value;

      if (UNLIKELY (! json_object_is_type (op, json_type_string)))
        {
          ret = crun_make_error (err, 0, "%s: `ops` must contain strings", IO_URING_ANNOTATION);
          goto exit;
        }
      name = json_object_get_string (op);
      value = find_op (name);
      /* Possibly an operation newer than crun: denied, like any not in `ops`.  */
      if (UNLIKELY (value < 0))
        {
          if (warn)
            libcrun_warning ("%s: unknown io_uring operation `%s` ignored", IO_URING_ANNOTATION, name);
          continue;
        }
      policy->ops[value] = true;
    }

  if (json_object_object_get_ex (doc, "socketFamilies", &families))
    {
      if (UNLIKELY (! json_object_is_type (families, json_type_array)))
        {
          ret = crun_make_error (err, 0, "%s: `socketFamilies` must be an array", IO_URING_ANNOTATION);
          goto exit;
        }

      len = json_object_array_length (families);
      if (UNLIKELY (len == 0))
        {
          ret = crun_make_error (err, 0, "%s: `socketFamilies` must not be empty; to deny all sockets, leave IORING_OP_SOCKET out of `ops`",
                                 IO_URING_ANNOTATION);
          goto exit;
        }

      if (UNLIKELY (! policy->ops[IORING_OP_SOCKET_VALUE]))
        {
          ret = crun_make_error (err, 0, "%s: `socketFamilies` requires IORING_OP_SOCKET in `ops`", IO_URING_ANNOTATION);
          goto exit;
        }

      for (i = 0; i < len; i++)
        {
          json_object *family = json_object_array_get_idx (families, i);

          if (UNLIKELY (! json_object_is_type (family, json_type_string)))
            {
              ret = crun_make_error (err, 0, "%s: `socketFamilies` must contain strings", IO_URING_ANNOTATION);
              goto exit;
            }
          add_socket_family (policy, json_object_get_string (family), warn);
        }

      /* With no known family, deny IORING_OP_SOCKET: never allow any family.  */
      if (policy->socket_families_len == 0)
        policy->ops[IORING_OP_SOCKET_VALUE] = false;
      else
        policy->has_socket_families = true;
    }

  ret = 0;

exit:
  json_object_put (doc);
  return ret;
}

static int
syscall_io_uring_register (int fd, unsigned int opcode, void *arg, unsigned int nr_args)
{
#ifdef __NR_io_uring_register
  return syscall (__NR_io_uring_register, fd, opcode, arg, nr_args);
#else
  (void) fd;
  (void) opcode;
  (void) arg;
  (void) nr_args;
  errno = ENOSYS;
  return -1;
#endif
}

/* Register with a NULL argument: a kernel with task-level BPF filters fails
   to copy it (EFAULT), or refuses the caller before that (EACCES).  Older
   kernels reject fd -1 (EBADF) or the opcode (EINVAL), as does a kernel built
   without CONFIG_IO_URING_BPF; seccomp may deny the syscall.  Returns 0 if
   supported, otherwise the errno.  */
static int
probe_io_uring_restrictions ()
{
  int ret;

  ret = syscall_io_uring_register (-1, CRUN_IORING_REGISTER_BPF_FILTER, NULL, 1);
  if (ret < 0 && (errno == EFAULT || errno == EACCES))
    return 0;
  return ret < 0 ? errno : EINVAL;
}

static int
register_filter (uint32_t opcode, uint32_t flags, struct sock_filter *program, size_t program_len)
{
  struct crun_io_uring_bpf bpf;

  memset (&bpf, 0, sizeof (bpf));
  bpf.cmd_type = CRUN_IO_URING_BPF_CMD_FILTER;
  bpf.filter.opcode = opcode;
  bpf.filter.flags = flags;
  bpf.filter.filter_len = program_len;
  bpf.filter.filter_ptr = (uint64_t) (uintptr_t) program;

  /* fd -1 registers the filter for the calling task.  It is inherited
     across fork and exec, like seccomp.  */
  return syscall_io_uring_register (-1, CRUN_IORING_REGISTER_BPF_FILTER, &bpf, 1);
}

static int
apply_policy (struct io_uring_policy_s *policy, libcrun_error_t *err)
{
  struct sock_filter allow[] = {
    BPF_STMT (BPF_RET | BPF_K, 1),
  };
  struct sock_filter deny[] = {
    BPF_STMT (BPF_RET | BPF_K, 0),
  };
  struct sock_filter socket_program[IO_URING_SOCKET_FAMILIES_LEN + 3];
  size_t socket_program_len = 0;
  uint32_t op;
  int ret;

  if (policy->has_socket_families)
    {
      size_t n = policy->socket_families_len;
      size_t j;

      socket_program[socket_program_len++] = (struct sock_filter) BPF_STMT (BPF_LD | BPF_W | BPF_ABS, CRUN_IO_URING_BPF_CTX_PDU_OFFSET);
      /* On a match, jump over the remaining comparisons and the deny.  */
      for (j = 0; j < n; j++)
        socket_program[socket_program_len++] = (struct sock_filter) BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, policy->socket_families[j], n - j, 0);
      socket_program[socket_program_len++] = (struct sock_filter) BPF_STMT (BPF_RET | BPF_K, 0);
      socket_program[socket_program_len++] = (struct sock_filter) BPF_STMT (BPF_RET | BPF_K, 1);
    }

  /* Every opcode gets a filter: DENY_REST only fills the opcodes without
     one, so an opcode that a filter inherited by crun allows would stay
     allowed.  With these fixed programs, EINVAL only means that the kernel
     doesn't know this opcode, nor the later ones.  IORING_OP_SOCKET with
     socketFamilies is registered after the loop, where EINVAL is an error.  */
  for (op = 0; op < IO_URING_MAX_OPCODES; op++)
    {
      bool allowed = op < IO_URING_OPS_LEN && policy->ops[op];

      if (allowed && op == IORING_OP_SOCKET_VALUE && policy->has_socket_families)
        continue;

      ret = register_filter (op, 0, allowed ? allow : deny, 1);
      if (UNLIKELY (ret < 0))
        {
          if (errno == EINVAL && op > 0)
            break;
          return crun_make_error (err, errno, "register io_uring filter for opcode %" PRIu32, op);
        }
    }

  if (policy->has_socket_families && op > IORING_OP_SOCKET_VALUE)
    {
      ret = register_filter (IORING_OP_SOCKET_VALUE, 0, socket_program, socket_program_len);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "register io_uring filter for `%s`", io_uring_ops[IORING_OP_SOCKET_VALUE]);
    }

  return 0;
}

/* In a constructor, as the process is /proc/self/exe: crun or any program
   using libcrun.  */
__attribute__ ((constructor)) static void
io_uring_exec_check (void)
{
  int ret;

  if (getenv (IO_URING_EXEC_CHECK_ENV) == NULL)
    return;

  /* With task restrictions, registering classic ones fails with EPERM.  */
  ret = syscall_io_uring_register (-1, CRUN_IORING_REGISTER_RESTRICTIONS, NULL, 1);
  _exit (ret < 0 && errno == EPERM ? EXIT_SUCCESS : EXIT_FAILURE);
}

/* On Linux 7.0 and 7.1 without bc0e8faf90e7, a task that has used io_uring
   loses its restrictions on exec.  Check it on a child that restricts
   itself, creates a ring and execs crun.  */
static int
check_restrictions_kept_on_exec (libcrun_error_t *err)
{
#ifdef __NR_io_uring_setup
  struct sock_filter deny[] = {
    BPF_STMT (BPF_RET | BPF_K, 0),
  };
  char *argv[] = { (char *) "crun", NULL };
  char *envp[] = { (char *) IO_URING_EXEC_CHECK_ENV "=1", NULL };
  /* Room for struct io_uring_params.  */
  uint64_t params[16];
  int fds[2], child_errno, status, ret;
  pid_t pid;

  ret = pipe2 (fds, O_CLOEXEC);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");

  pid = fork ();
  if (UNLIKELY (pid < 0))
    {
      ret = crun_make_error (err, errno, "fork");
      close (fds[0]);
      close (fds[1]);
      return ret;
    }
  if (pid == 0)
    {
      memset (params, 0, sizeof (params));
      if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
          && register_filter (IORING_OP_NOP_VALUE, 0, deny, 1) == 0
          && syscall (__NR_io_uring_setup, 1, params) >= 0)
        execve ("/proc/self/exe", argv, envp);
      child_errno = errno;
      TEMP_FAILURE_RETRY (write (fds[1], &child_errno, sizeof (child_errno)));
      _exit (EXIT_FAILURE);
    }

  close (fds[1]);
  ret = TEMP_FAILURE_RETRY (read (fds[0], &child_errno, sizeof (child_errno)));
  close (fds[0]);

  if (UNLIKELY (waitpid_ignore_stopped (pid, &status, 0) < 0))
    return crun_make_error (err, errno, "waitpid");

  if (UNLIKELY (ret == sizeof (child_errno)))
    return crun_make_error (err, child_errno, "%s: cannot check that the kernel keeps io_uring restrictions on exec", IO_URING_ANNOTATION);

  if (UNLIKELY (! WIFEXITED (status) || WEXITSTATUS (status) != EXIT_SUCCESS))
    return crun_make_error (err, 0, "%s: the kernel does not keep io_uring restrictions on exec (Linux 7.0 and 7.1 need commit bc0e8faf90e7)",
                            IO_URING_ANNOTATION);

  return 0;
#else
  return crun_make_error (err, ENOSYS, "%s: cannot check that the kernel keeps io_uring restrictions on exec", IO_URING_ANNOTATION);
#endif
}

int
libcrun_check_io_uring_restrictions (libcrun_container_t *container, libcrun_error_t *err)
{
  struct io_uring_policy_s policy;
  const char *annotation;
  int ret;

  annotation = find_annotation (container, IO_URING_ANNOTATION);
  if (annotation == NULL)
    return 0;

  ret = parse_policy (annotation, &policy, true, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = probe_io_uring_restrictions ();
  if (UNLIKELY (ret != 0))
    return crun_make_error (err, ret, "%s: io_uring restrictions are not supported or not permitted (Linux 7.0 or newer is required)",
                            IO_URING_ANNOTATION);

  return check_restrictions_kept_on_exec (err);
}

int
libcrun_apply_io_uring_restrictions (libcrun_container_t *container, libcrun_error_t *err)
{
  struct io_uring_policy_s policy;
  const char *annotation;
  int ret;

  annotation = find_annotation (container, IO_URING_ANNOTATION);
  if (annotation == NULL)
    return 0;

  ret = parse_policy (annotation, &policy, false, err);
  if (UNLIKELY (ret < 0))
    return ret;

  libcrun_debug ("Applying io_uring restrictions");

  return apply_policy (&policy, err);
}
