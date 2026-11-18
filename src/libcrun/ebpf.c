/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include "ebpf.h"
#include "utils.h"
#include "cgroup-resources.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#ifdef HAVE_EBPF
#  include <linux/bpf.h>

#  ifndef HAVE_BPF
static int
syscall_bpf (int cmd, union bpf_attr *attr, unsigned int size)
{
  return (int) syscall (__NR_bpf, cmd, attr, size);
}
#    define bpf syscall_bpf
#  endif

#endif

static inline uint64_t
ptr_to_u64 (const void *ptr)
{
  return (uint64_t) (unsigned long) ptr;
}

enum
{
  HAS_WILDCARD = 1
};

struct bpf_program
{
  size_t allocated;
  size_t used;
  unsigned int private;
  char program[];
};

#ifdef HAVE_EBPF

#  define BPF_ALU32_IMM(OP, DST, IMM) \
    ((struct bpf_insn) { .code = BPF_ALU | BPF_OP (OP) | BPF_K, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

#  define BPF_LDX_MEM(SIZE, DST, SRC, OFF) \
    ((struct bpf_insn) {                   \
        .code = BPF_LDX | BPF_SIZE (SIZE) | BPF_MEM, .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0 })

#  define BPF_MOV64_REG(DST, SRC) \
    ((struct bpf_insn) { .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0 })

#  define BPF_JMP_A(OFF) \
    ((struct bpf_insn) { .code = BPF_JMP | BPF_JA, .dst_reg = 0, .src_reg = 0, .off = OFF, .imm = 0 })

#  define BPF_JMP_IMM(OP, DST, IMM, OFF) \
    ((struct bpf_insn) { .code = BPF_JMP | BPF_OP (OP) | BPF_K, .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM })

#  define BPF_JMP_REG(OP, DST, SRC, OFF) \
    ((struct bpf_insn) { .code = BPF_JMP | BPF_OP (OP) | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0 })

#  define BPF_MOV64_IMM(DST, IMM) \
    ((struct bpf_insn) { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

#  define BPF_MOV32_REG(DST, SRC) \
    ((struct bpf_insn) { .code = BPF_ALU | BPF_MOV | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0 })

#  define BPF_EXIT_INSN() \
    ((struct bpf_insn) { .code = BPF_JMP | BPF_EXIT, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 })
#endif

#ifdef HAVE_EBPF
static size_t
bpf_program_instructions (struct bpf_program *program)
{
  return program->used / (sizeof (struct bpf_insn));
}
#endif

struct bpf_program *
bpf_program_new (size_t size)
{
  struct bpf_program *p = xmalloc (size + sizeof (struct bpf_program));

  p->used = 0;
  p->private = 0;
  p->allocated = size;

  return p;
}

struct bpf_program *
bpf_program_append (struct bpf_program *p, void *data, size_t size)
{
  if (p->allocated <= p->used + size)
    {
      p->allocated += size * 2;
      p = xrealloc (p, p->allocated + sizeof (struct bpf_program));
    }
  memcpy (p->program + p->used, data, size);
  p->used += size;
  return p;
}

struct bpf_program *
bpf_program_init_dev (struct bpf_program *program, libcrun_error_t *err arg_unused)
{
#ifdef HAVE_EBPF
  /* taken from systemd.  */
  struct bpf_insn pre_insn[] = {
    /* type -> R2.  */
    BPF_LDX_MEM (BPF_W, BPF_REG_2, BPF_REG_1, 0),
    BPF_ALU32_IMM (BPF_AND, BPF_REG_2, 0xFFFF),

    /* access -> R3.  */
    BPF_LDX_MEM (BPF_W, BPF_REG_3, BPF_REG_1, 0),
    BPF_ALU32_IMM (BPF_RSH, BPF_REG_3, 16),

    /* major -> R4.  */
    BPF_LDX_MEM (BPF_W, BPF_REG_4, BPF_REG_1, 4),

    /* minor -> R5.  */
    BPF_LDX_MEM (BPF_W, BPF_REG_5, BPF_REG_1, 8),
  };
  program = bpf_program_append (program, pre_insn, sizeof (pre_insn));
#endif
  return program;
}

struct bpf_program *
bpf_program_append_dev (struct bpf_program *program, const char *access, char type, int major, int minor, bool accept,
                        libcrun_error_t *err arg_unused)
{
#ifdef HAVE_EBPF
  int i;
  int bpf_access = 0;
  int bpf_type = type == 'b' ? BPF_DEVCG_DEV_BLOCK : BPF_DEVCG_DEV_CHAR;
  bool has_type = type != 'a';
  bool has_major = major >= 0;
  bool has_minor = minor >= 0;
  bool has_access = false;
  int number_instructions = 0;
  struct bpf_insn accept_block[] = {
    BPF_MOV64_IMM (BPF_REG_0, accept ? 1 : 0),
    BPF_EXIT_INSN (),
  };

  if (access == NULL)
    access = "";

  if (program->private & HAS_WILDCARD)
    return program;

  for (i = 0; access[i]; i++)
    {
      switch (access[i])
        {
        case 'r':
          bpf_access |= BPF_DEVCG_ACC_READ;
          break;

        case 'w':
          bpf_access |= BPF_DEVCG_ACC_WRITE;
          break;

        case 'm':
          bpf_access |= BPF_DEVCG_ACC_MKNOD;
          break;
        }
    }

  /*
    if (request.type != device.type)
      goto next_block:
    if (accept && (request.access & device.access) != request.access)
      goto next_block:
    if (! accept && (request.access & device.access) == 0)
      goto next_block:
    if (device.major != '*' && request.major != device.major) == 0)
      goto next_block:
    if (device.minor != '*' && request.minor != device.minor) == 0)
      goto next_block:
    return accept_or_reject;
  next_block:
  */

  /* If the access is rwm, skip the check.  */
  has_access = bpf_access != (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD);

  /* Number of instructions to skip the ACCEPT BLOCK.  */
  number_instructions = (has_type ? 1 : 0) + (has_access ? 3 : 0) + (has_major ? 1 : 0) + (has_minor ? 1 : 0) + 1;

  if (has_type)
    {
      struct bpf_insn i[] = { BPF_JMP_IMM (BPF_JNE, BPF_REG_2, bpf_type, number_instructions) };
      number_instructions--;
      program = bpf_program_append (program, i, sizeof (i));
    }
  if (has_access)
    {
      struct bpf_insn i[] = {
        BPF_MOV32_REG (BPF_REG_1, BPF_REG_3),
        BPF_ALU32_IMM (BPF_AND, BPF_REG_1, bpf_access),
        accept ? BPF_JMP_REG (BPF_JNE, BPF_REG_1, BPF_REG_3, number_instructions - 2)
               : BPF_JMP_IMM (BPF_JEQ, BPF_REG_1, 0, number_instructions - 2),
      };
      number_instructions -= 3;
      program = bpf_program_append (program, i, sizeof (i));
    }
  if (has_major)
    {
      struct bpf_insn i[] = { BPF_JMP_IMM (BPF_JNE, BPF_REG_4, major, number_instructions) };
      number_instructions--;
      program = bpf_program_append (program, i, sizeof (i));
    }
  if (has_minor)
    {
      struct bpf_insn i[] = { BPF_JMP_IMM (BPF_JNE, BPF_REG_5, minor, number_instructions) };
      number_instructions--;
      program = bpf_program_append (program, i, sizeof (i));
    }

  if (has_type == 0 && has_access == 0 && has_major == 0 && has_minor == 0)
    program->private |= HAS_WILDCARD;

  program = bpf_program_append (program, accept_block, sizeof (accept_block));
#endif
  (void) access;
  (void) type;
  (void) major;
  (void) minor;
  (void) accept;

  return program;
}

struct bpf_program *
bpf_program_complete_dev (struct bpf_program *program, libcrun_error_t *err arg_unused)
{
#ifdef HAVE_EBPF
  struct bpf_insn i[] = {
    BPF_MOV64_IMM (BPF_REG_0, 0),
    BPF_EXIT_INSN (),
  };

  if (program->private & HAS_WILDCARD)
    return program;

  program = bpf_program_append (program, &i, sizeof (i));
#endif
  return program;
}

static int
read_all_progs (int dirfd, uint32_t **progs_out, size_t *n_progs_out, libcrun_error_t *err)
{
#ifdef HAVE_EBPF
  cleanup_free uint32_t *progs = NULL;
  union bpf_attr attr;
  int ret;
  size_t cur_size;

  /* The kernel 5.7 has a hard limit of 64, let's be safe if the limit
     will be increased in future and attempt up to 4096.  */
  for (cur_size = 64; cur_size <= 4096; cur_size *= 2)
    {
      progs = xrealloc (progs, sizeof (uint32_t) * cur_size);

      memset (&attr, 0, sizeof (attr));
      attr.query.target_fd = dirfd;
      attr.query.attach_type = BPF_CGROUP_DEVICE;
      attr.query.prog_cnt = cur_size;
      attr.query.prog_ids = ptr_to_u64 (progs);

      ret = bpf (BPF_PROG_QUERY, &attr, sizeof (attr));
      if (ret >= 0 || errno != ENOSPC)
        break;
    }

  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "bpf query");

  *progs_out = progs;
  progs = NULL;
  *n_progs_out = attr.query.prog_cnt;
  return 0;
#else
  (void) dirfd;

  *progs_out = NULL;
  *n_progs_out = 0;

  return crun_make_error (err, 0, "eBPF not supported");
#endif
}

static int
remove_all_progs (int dirfd, uint32_t *progs, size_t n_progs, libcrun_error_t *err)
{
#ifdef HAVE_EBPF
  union bpf_attr attr;
  size_t i;

  for (i = 0; i < n_progs; i++)
    {
      cleanup_close int fd = -1;
      int ret;

      memset (&attr, 0, sizeof (attr));
      attr.prog_id = progs[i];
      fd = bpf (BPF_PROG_GET_FD_BY_ID, &attr, sizeof (attr));
      if (UNLIKELY (fd < 0))
        {
          /* Already removed.  Nothing to do.  */
          if (errno == ENOENT)
            continue;

          return crun_make_error (err, errno, "cannot open existing eBPF program");
        }

      memset (&attr, 0, sizeof (attr));
      attr.attach_type = BPF_CGROUP_DEVICE;
      attr.target_fd = dirfd;
      attr.attach_bpf_fd = fd;

      ret = bpf (BPF_PROG_DETACH, &attr, sizeof (attr));
      if (UNLIKELY (ret < 0))
        {
          /* Already removed.  Nothing to do.  */
          if (errno == ENOENT)
            continue;

          return crun_make_error (err, errno, "cannot detach eBPF program");
        }
    }
  return 0;
#else
  (void) dirfd;
  (void) progs;
  (void) n_progs;
  return crun_make_error (err, 0, "eBPF not supported");
#endif
}

static int
ebpf_attach_program (int fd, int dirfd, libcrun_error_t *err)
{
#ifndef HAVE_EBPF
  (void) fd;
  (void) dirfd;
  (void) read_all_progs;
  (void) remove_all_progs;

  return crun_make_error (err, 0, "eBPF not supported");
#else
#  ifdef BPF_F_REPLACE
  bool skip_replace = false;
#  endif
  const int MAX_ATTEMPTS = 20;
  int attempt;

  for (attempt = 0;; attempt++)
    {
      cleanup_free uint32_t *progs = NULL;
      cleanup_close int replacefd = -1;
      union bpf_attr attr;
      size_t n_progs = 0;
      int ret;

      ret = read_all_progs (dirfd, &progs, &n_progs, err);
      if (UNLIKELY (ret < 0))
        return ret;

#  ifdef BPF_F_REPLACE
      /* There is just one program installed, let's attempt an atomic replace if supported.  */
      if (! skip_replace && n_progs == 1)
        {
          memset (&attr, 0, sizeof (attr));
          attr.prog_id = progs[0];
          replacefd = bpf (BPF_PROG_GET_FD_BY_ID, &attr, sizeof (attr));
          if (UNLIKELY (replacefd < 0))
            {
              if (errno == ENOENT && attempt < MAX_ATTEMPTS)
                {
                  /* Another update might have raced and updated, try again.  */
                  continue;
                }
              return crun_make_error (err, errno, "cannot open existing eBPF program");
            }
        }
#  endif

      memset (&attr, 0, sizeof (attr));
      attr.attach_type = BPF_CGROUP_DEVICE;
      attr.target_fd = dirfd;
      attr.attach_bpf_fd = fd;
      attr.attach_flags = BPF_F_ALLOW_MULTI;
#  ifdef BPF_F_REPLACE
      if (replacefd >= 0)
        {
          attr.attach_flags = BPF_F_ALLOW_MULTI | BPF_F_REPLACE;
          attr.replace_bpf_fd = replacefd;
        }
#  endif

      ret = bpf (BPF_PROG_ATTACH, &attr, sizeof (attr));
      if (UNLIKELY (ret < 0))
        {
          if (errno == ENOENT && replacefd >= 0 && attempt < MAX_ATTEMPTS)
            {
              /* Another update might have already updated the cgroup, try again.  */
              continue;
            }
#  ifdef BPF_F_REPLACE
          if (errno == EINVAL && replacefd >= 0)
            {
              skip_replace = true;
              continue;
            }
#  endif
          return crun_make_error (err, errno, "bpf attach");
        }

      /* Now that the new program is installed, remove all the programs that were previously installed.  */
      if (replacefd < 0 && n_progs)
        return remove_all_progs (dirfd, progs, n_progs, err);

      return 0;
    }
#endif
}

static void
bump_memlock ()
{
  struct rlimit limit;
  int ret;

  limit.rlim_cur = RLIM_INFINITY;
  limit.rlim_max = RLIM_INFINITY;

  ret = setrlimit (RLIMIT_MEMLOCK, &limit);
  if (ret == 0)
    return;

  /* If the above failed, try to set the current limit
     to the max configured.  */
  ret = getrlimit (RLIMIT_MEMLOCK, &limit);
  if (ret < 0)
    return;

  limit.rlim_cur = limit.rlim_max;
  /* Best effort, ignore errors.  */
  (void) setrlimit (RLIMIT_MEMLOCK, &limit);
}

#ifdef HAVE_EBPF
static int
ebpf_prog_load (const void *insns, size_t n_insns, const char *name, libcrun_error_t *err)
{
  cleanup_close int fd = -1;
  union bpf_attr attr;

  memset (&attr, 0, sizeof (attr));
  attr.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
  attr.insns = ptr_to_u64 (insns);
  attr.insn_cnt = n_insns;
  attr.license = ptr_to_u64 ("GPL");
  if (name)
    stpncpy (attr.prog_name, name, sizeof (attr.prog_name) - 1);

  /* First try without log.  */
  fd = bpf (BPF_PROG_LOAD, &attr, sizeof (attr));
  if (fd < 0)
    {
      /* Prior to Linux 5.11, eBPF programs were accounted to the memlock
         prlimit.  Attempt to bump the limit, if possible.  */
      bump_memlock ();
      fd = bpf (BPF_PROG_LOAD, &attr, sizeof (attr));
    }
  if (fd < 0)
    {
      const size_t max_log_size = 1 << 20;
      cleanup_free char *log = NULL;
      size_t log_size = 8192;

    retry:
      log = xrealloc (log, log_size);
      log[0] = '\0';
      attr.log_level = 1;
      attr.log_buf = ptr_to_u64 (log);
      attr.log_size = log_size;

      fd = bpf (BPF_PROG_LOAD, &attr, sizeof (attr));
      if (fd < 0)
        {
          if (errno == ENOSPC && log_size < max_log_size)
            {
              /* The provided buffer was not big enough.  */
              log_size *= 2;
              goto retry;
            }
          return crun_make_error (err, errno, "bpf create `%s`", log);
        }
    }

  return get_and_reset (&fd);
}

static int
ebpf_pin (int fd, const char *pin, libcrun_error_t *err)
{
  union bpf_attr attr;
  int ret;

  memset (&attr, 0, sizeof (attr));
  attr.pathname = ptr_to_u64 (pin);
  attr.bpf_fd = fd;
  ret = bpf (BPF_OBJ_PIN, &attr, sizeof (attr));
  if (ret < 0)
    return crun_make_error (err, errno, "bpf pin to `%s`", pin);
  return 0;
}
#endif

int
libcrun_ebpf_load (struct bpf_program *program, int dirfd, const char *pin, libcrun_error_t *err)
{
#ifndef HAVE_EBPF
  (void) dirfd;
  (void) program;
  (void) pin;
  (void) ebpf_attach_program;

  return crun_make_error (err, 0, "eBPF not supported");
#else
  cleanup_close int fd = -1;
  int ret;

  fd = ebpf_prog_load (program->program, bpf_program_instructions (program), NULL, err);
  if (UNLIKELY (fd < 0))
    return fd;

  if (dirfd >= 0)
    {
      ret = ebpf_attach_program (fd, dirfd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Optionally pin the program to the specified path.  */
  if (pin)
    {
      unlink (pin);

      ret = ebpf_pin (fd, pin, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
#endif
}

int
libcrun_ebpf_read_program (struct bpf_program **program_ret, const char *path, libcrun_error_t *err)
{
#ifndef HAVE_EBPF
  (void) program_ret;
  (void) path;

  return crun_make_error (err, 0, "eBPF not supported");
#else
  cleanup_free struct bpf_program *program = NULL;
  cleanup_free char *buffer = NULL;
  cleanup_close int prog_fd = -1;
  size_t buffer_size = 0;
  struct bpf_prog_info info;
  union bpf_attr attr;
  int ret;

  memset (&attr, 0, sizeof (attr));
  attr.pathname = ptr_to_u64 (path);

  prog_fd = bpf (BPF_OBJ_GET, &attr, sizeof (attr));
  if (UNLIKELY (prog_fd < 0))
    return crun_make_error (err, errno, "bpf get `%s`", path);

  memset (&info, 0, sizeof (info));

  memset (&attr, 0, sizeof (attr));
  attr.info.bpf_fd = prog_fd;
  attr.info.info = ptr_to_u64 (&info);
  attr.info.info_len = sizeof (info);

  ret = bpf (BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof (attr));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "bpf get info `%s`", path);

  buffer_size = info.xlated_prog_len;
  buffer = xmalloc (buffer_size);

  memset (&info, 0, sizeof (info));
  info.xlated_prog_insns = ptr_to_u64 (buffer);
  info.xlated_prog_len = buffer_size;

  ret = bpf (BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof (attr));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "bpf get info `%s`", path);

  program = bpf_program_new (buffer_size);
  program = bpf_program_append (program, buffer, buffer_size);

  *program_ret = program;
  program = NULL;

  return 0;
#endif
}

int
libcrun_ebpf_query_cgroup_progs (const char *cgroup_path, uint32_t **progs_out, size_t *n_progs_out, libcrun_error_t *err)
{
#ifndef HAVE_EBPF
  (void) cgroup_path;
  *progs_out = NULL;
  *n_progs_out = 0;
  return crun_make_error (err, 0, "eBPF not supported");
#else
  cleanup_close int cgroup_fd = -1;

  cgroup_fd = open (cgroup_path, O_PATH | O_CLOEXEC);
  if (UNLIKELY (cgroup_fd < 0))
    return crun_make_error (err, errno, "open cgroup path `%s`", cgroup_path);

  return read_all_progs (cgroup_fd, progs_out, n_progs_out, err);
#endif
}

bool
libcrun_ebpf_cmp_programs (struct bpf_program *program1, struct bpf_program *program2)
{
  if (program1->used != program2->used)
    return false;

  return memcmp (program1->program, program2->program, program1->used) == 0;
}

#ifdef HAVE_EBPF

#  define CRUN_DEV_PROG_NAME "crun_dev_v1"
#  define CRUN_DEV_MAP_NAME "crun_dev_rules"

enum
{
  DEV_RULE_BLOCK = 1,
  DEV_RULE_CHAR = 2,
  DEV_RULE_ALLOW = 4,
  DEV_RULE_ANY_MAJOR = 8,
  DEV_RULE_ANY_MINOR = 16,
  DEV_RULE_VALID = 32,
};

struct dev_rule
{
  uint32_t flags;
  uint32_t access;
  uint32_t major;
  uint32_t minor;
};

struct dev_rules
{
  struct dev_rule rules[CRUN_DEV_MAX_RULES];
};

struct dev_rules_builder
{
  struct dev_rules *table;
  size_t n;
  bool wildcard;
};

static bool
dev_rule_is_wildcard (const struct dev_rule *rule)
{
  uint32_t all = DEV_RULE_BLOCK | DEV_RULE_CHAR | DEV_RULE_ANY_MAJOR | DEV_RULE_ANY_MINOR;

  return (rule->flags & all) == all && rule->access == (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD);
}

static int
dev_rules_append_record (struct dev_rules_builder *b, const struct dev_rule *rule, libcrun_error_t *err)
{
  /* Rules following a rule that matches everything can never be reached.  */
  if (b->wildcard)
    return 0;

  if (b->n >= CRUN_DEV_MAX_RULES)
    return crun_make_error (err, E2BIG, "too many device rules: at most %d are supported, including the default devices",
                            CRUN_DEV_MAX_RULES);

  b->table->rules[b->n++] = *rule;

  if (dev_rule_is_wildcard (rule))
    b->wildcard = true;

  return 0;
}

static int
dev_rules_append (struct dev_rules_builder *b, const char *access, char type, int major, int minor, bool allow,
                  libcrun_error_t *err)
{
  struct dev_rule rule;
  size_t i;

  memset (&rule, 0, sizeof (rule));

  if (access == NULL)
    access = "";

  for (i = 0; access[i]; i++)
    {
      switch (access[i])
        {
        case 'r':
          rule.access |= BPF_DEVCG_ACC_READ;
          break;

        case 'w':
          rule.access |= BPF_DEVCG_ACC_WRITE;
          break;

        case 'm':
          rule.access |= BPF_DEVCG_ACC_MKNOD;
          break;
        }
    }

  rule.flags = DEV_RULE_VALID;
  if (type == 'a')
    rule.flags |= DEV_RULE_BLOCK | DEV_RULE_CHAR;
  else if (type == 'b')
    rule.flags |= DEV_RULE_BLOCK;
  else
    rule.flags |= DEV_RULE_CHAR;
  if (allow)
    rule.flags |= DEV_RULE_ALLOW;

  if (major >= 0)
    rule.major = major;
  else
    rule.flags |= DEV_RULE_ANY_MAJOR;

  if (minor >= 0)
    rule.minor = minor;
  else
    rule.flags |= DEV_RULE_ANY_MINOR;

  return dev_rules_append_record (b, &rule, err);
}

/* Build the table in the same order that create_dev_bpf emits the checks: the first match wins.  */
static int
dev_rules_build (struct dev_rules *table, runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len,
                 libcrun_error_t *err)
{
  struct default_dev_s *default_devices = get_default_devices ();
  struct dev_rules_builder b = { .table = table };
  size_t n_default;
  int i, ret;

  for (n_default = 0; default_devices[n_default].type; n_default++)
    ;

  for (i = (int) n_default - 1; i >= 0; i--)
    {
      ret = dev_rules_append (&b, default_devices[i].access, default_devices[i].type, default_devices[i].major,
                              default_devices[i].minor, true, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  for (i = (int) devs_len - 1; i >= 0; i--)
    {
      char type = 'a';
      int minor = -1, major = -1;

      if (devs[i]->type != NULL)
        type = devs[i]->type[0];
      if (devs[i]->major_present)
        major = devs[i]->major;
      if (devs[i]->minor_present)
        minor = devs[i]->minor;

      ret = dev_rules_append (&b, devs[i]->access, type, major, minor, devs[i]->allow, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  return 0;
}

static int
ebpf_map_create (union bpf_attr *attr, const char *name, libcrun_error_t *err)
{
  int fd;

  stpncpy (attr->map_name, name, sizeof (attr->map_name) - 1);

  fd = bpf (BPF_MAP_CREATE, attr, sizeof (*attr));
  if (fd < 0)
    {
      /* Prior to Linux 5.11, maps were accounted to the memlock prlimit.  */
      bump_memlock ();
      fd = bpf (BPF_MAP_CREATE, attr, sizeof (*attr));
    }
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "bpf create map `%s`", name);
  return fd;
}

/* The rules are stored in a map that has a separate value for each cgroup the program is attached to.  */
static int
dev_create_storage_map (libcrun_error_t *err)
{
  union bpf_attr attr;

  memset (&attr, 0, sizeof (attr));
  attr.map_type = BPF_MAP_TYPE_CGROUP_STORAGE;
  attr.key_size = sizeof (struct bpf_cgroup_storage_key);
  attr.value_size = sizeof (struct dev_rules);

  return ebpf_map_create (&attr, CRUN_DEV_MAP_NAME, err);
}

enum
{
  L_LOOP,
  L_NEXT,
  L_COUNT,
};

#  define ASM_MAX_INSNS 96
#  define ASM_MAX_FIXUPS 32

/* A minimal assembler.  A limit that is exceeded sets ERROR, which is checked once after the program is built.  */
struct asm_ctx
{
  struct bpf_insn insns[ASM_MAX_INSNS];
  size_t n;
  int label_pos[L_COUNT];
  struct
  {
    size_t insn;
    int label;
  } fixups[ASM_MAX_FIXUPS];
  size_t n_fixups;
  bool error;
};

static void
asm_init (struct asm_ctx *a)
{
  int i;

  memset (a, 0, sizeof (*a));
  for (i = 0; i < L_COUNT; i++)
    a->label_pos[i] = -1;
}

static void
asm_emit (struct asm_ctx *a, struct bpf_insn insn)
{
  if (a->n >= ASM_MAX_INSNS)
    {
      a->error = true;
      return;
    }
  a->insns[a->n++] = insn;
}

static void
asm_jump (struct asm_ctx *a, struct bpf_insn insn, int label)
{
  if (label < 0 || label >= L_COUNT || a->n_fixups >= ASM_MAX_FIXUPS || a->n >= ASM_MAX_INSNS)
    {
      a->error = true;
      return;
    }
  a->fixups[a->n_fixups].insn = a->n;
  a->fixups[a->n_fixups].label = label;
  a->n_fixups++;
  asm_emit (a, insn);
}

static void
asm_label (struct asm_ctx *a, int label)
{
  if (label < 0 || label >= L_COUNT)
    {
      a->error = true;
      return;
    }
  a->label_pos[label] = (int) a->n;
}

static void
asm_resolve (struct asm_ctx *a)
{
  size_t i;

  for (i = 0; i < a->n_fixups; i++)
    {
      size_t at = a->fixups[i].insn;
      int target = a->label_pos[a->fixups[i].label];
      int off = target - (int) at - 1;

      /* A label that was never placed, or a jump that does not fit the offset field.  */
      if (target < 0 || off < INT16_MIN || off > INT16_MAX)
        {
          a->error = true;
          return;
        }
      a->insns[at].off = off;
    }
}

#  define BPF_ALU64_IMM(OP, DST, IMM) \
    ((struct bpf_insn) { .code = BPF_ALU64 | BPF_OP (OP) | BPF_K, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

#  define BPF_ALU64_REG(OP, DST, SRC) \
    ((struct bpf_insn) { .code = BPF_ALU64 | BPF_OP (OP) | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0 })

#  define BPF_ALU64_NEG(DST) \
    ((struct bpf_insn) { .code = BPF_ALU64 | BPF_NEG, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = 0 })

#  define BPF_CALL_FUNC(FUNC) \
    ((struct bpf_insn) { .code = BPF_JMP | BPF_CALL, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = FUNC })

/*
 * Linear scan of the rules stored in the map:
 *
 *   rules = get_local_storage (map)
 *   for (i = 0; i < CRUN_DEV_MAX_RULES; i++, rules++)
 *     {
 *       if (! (rules->flags & VALID)) break;
 *       if (! (rules->flags & request.type)) continue;
 *       if (allow rule && (request.access & rules->access) != request.access) continue;
 *       if (deny rule && (request.access & rules->access) == 0) continue;
 *       if (! ANY_MAJOR && rules->major != request.major) continue;
 *       if (! ANY_MINOR && rules->minor != request.minor) continue;
 *       return allow rule;
 *     }
 *   return 0;
 *
 * The verifier walks every iteration of the loop and keeps a copy of the state for each branch that it has still to
 * explore, so the body computes the result of a rule without branches and has a single conditional jump, whose
 * fall-through path exits.  The values loaded from the map are 32 bits, so (-x) >> 63 is 1 if x != 0 and 0 otherwise.
 */
static int
dev_build_program (struct asm_ctx *a, int map_fd, libcrun_error_t *err)
{
  asm_init (a);

  /* R6 = type, R7 = access, R8 = major, R9 = minor.  */
  asm_emit (a, BPF_LDX_MEM (BPF_W, BPF_REG_6, BPF_REG_1, 0));
  asm_emit (a, BPF_MOV64_REG (BPF_REG_7, BPF_REG_6));
  asm_emit (a, BPF_ALU64_IMM (BPF_AND, BPF_REG_6, 0xFFFF));
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_7, 16));
  asm_emit (a, BPF_LDX_MEM (BPF_W, BPF_REG_8, BPF_REG_1, 4));
  asm_emit (a, BPF_LDX_MEM (BPF_W, BPF_REG_9, BPF_REG_1, 8));

  /* R1 = the table of rules of the cgroup the program is attached to.  */
  asm_emit (a, ((struct bpf_insn) { .code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD, .imm = map_fd }));
  asm_emit (a, ((struct bpf_insn) { .code = 0, .imm = 0 }));
  asm_emit (a, BPF_MOV64_IMM (BPF_REG_2, 0));
  asm_emit (a, BPF_CALL_FUNC (BPF_FUNC_get_local_storage));
  asm_emit (a, BPF_MOV64_REG (BPF_REG_1, BPF_REG_0));

  /* R2 = loop counter.  */
  asm_emit (a, BPF_MOV64_IMM (BPF_REG_2, 0));

  asm_label (a, L_LOOP);
  /* R3 = flags.  */
  asm_emit (a, BPF_LDX_MEM (BPF_W, BPF_REG_3, BPF_REG_1, 0));

  /* R0 = the type does not match.  */
  asm_emit (a, BPF_MOV64_REG (BPF_REG_0, BPF_REG_3));
  asm_emit (a, BPF_ALU64_IMM (BPF_AND, BPF_REG_0, DEV_RULE_BLOCK | DEV_RULE_CHAR));
  asm_emit (a, BPF_ALU64_REG (BPF_AND, BPF_REG_0, BPF_REG_6));
  asm_emit (a, BPF_ALU64_NEG (BPF_REG_0));
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_0, 63));
  asm_emit (a, BPF_ALU64_IMM (BPF_XOR, BPF_REG_0, 1));

  /* R0 |= (rule.major ^ request.major) unless ANY_MAJOR.  */
  asm_emit (a, BPF_LDX_MEM (BPF_W, BPF_REG_4, BPF_REG_1, 8));
  asm_emit (a, BPF_ALU64_REG (BPF_XOR, BPF_REG_4, BPF_REG_8));
  asm_emit (a, BPF_MOV64_REG (BPF_REG_5, BPF_REG_3));
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_5, 3));
  asm_emit (a, BPF_ALU64_IMM (BPF_AND, BPF_REG_5, 1));
  asm_emit (a, BPF_ALU64_IMM (BPF_SUB, BPF_REG_5, 1));
  asm_emit (a, BPF_ALU64_REG (BPF_AND, BPF_REG_4, BPF_REG_5));
  asm_emit (a, BPF_ALU64_REG (BPF_OR, BPF_REG_0, BPF_REG_4));

  /* R0 |= (rule.minor ^ request.minor) unless ANY_MINOR.  */
  asm_emit (a, BPF_LDX_MEM (BPF_W, BPF_REG_4, BPF_REG_1, 12));
  asm_emit (a, BPF_ALU64_REG (BPF_XOR, BPF_REG_4, BPF_REG_9));
  asm_emit (a, BPF_MOV64_REG (BPF_REG_5, BPF_REG_3));
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_5, 4));
  asm_emit (a, BPF_ALU64_IMM (BPF_AND, BPF_REG_5, 1));
  asm_emit (a, BPF_ALU64_IMM (BPF_SUB, BPF_REG_5, 1));
  asm_emit (a, BPF_ALU64_REG (BPF_AND, BPF_REG_4, BPF_REG_5));
  asm_emit (a, BPF_ALU64_REG (BPF_OR, BPF_REG_0, BPF_REG_4));

  /* access: R4 = request.access & rule.access, R5 = the deny rule does not match (R4 == 0), R4 = the allow rule does
     not match (R4 != request.access).  */
  asm_emit (a, BPF_LDX_MEM (BPF_W, BPF_REG_4, BPF_REG_1, 4));
  asm_emit (a, BPF_ALU64_REG (BPF_AND, BPF_REG_4, BPF_REG_7));
  asm_emit (a, BPF_MOV64_REG (BPF_REG_5, BPF_REG_4));
  asm_emit (a, BPF_ALU64_NEG (BPF_REG_5));
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_5, 63));
  asm_emit (a, BPF_ALU64_IMM (BPF_XOR, BPF_REG_5, 1));
  asm_emit (a, BPF_ALU64_REG (BPF_XOR, BPF_REG_4, BPF_REG_7));
  asm_emit (a, BPF_ALU64_NEG (BPF_REG_4));
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_4, 63));
  /* R5 = ALLOW ? R4 : R5, using the ALLOW bit of the flags (bit 2) as a mask.  */
  asm_emit (a, BPF_ALU64_REG (BPF_XOR, BPF_REG_4, BPF_REG_5));
  asm_emit (a, BPF_ALU64_IMM (BPF_LSH, BPF_REG_4, 2));
  asm_emit (a, BPF_ALU64_REG (BPF_AND, BPF_REG_4, BPF_REG_3));
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_4, 2));
  asm_emit (a, BPF_ALU64_REG (BPF_XOR, BPF_REG_5, BPF_REG_4));
  asm_emit (a, BPF_ALU64_REG (BPF_OR, BPF_REG_0, BPF_REG_5));

  /* R4 = VALID, R0 = the rule matches.  */
  asm_emit (a, BPF_ALU64_NEG (BPF_REG_0));
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_0, 63));
  asm_emit (a, BPF_ALU64_IMM (BPF_XOR, BPF_REG_0, 1));
  asm_emit (a, BPF_MOV64_REG (BPF_REG_4, BPF_REG_3));
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_4, 5));
  asm_emit (a, BPF_ALU64_IMM (BPF_AND, BPF_REG_4, 1));
  asm_emit (a, BPF_ALU64_REG (BPF_AND, BPF_REG_0, BPF_REG_4));

  /* Continue unless the rule matches or it is the end of the list.  */
  asm_emit (a, BPF_ALU64_IMM (BPF_XOR, BPF_REG_4, 1));
  asm_emit (a, BPF_ALU64_REG (BPF_OR, BPF_REG_4, BPF_REG_0));
  asm_jump (a, BPF_JMP_IMM (BPF_JEQ, BPF_REG_4, 0, 0), L_NEXT);

  /* Return R0 & ALLOW.  */
  asm_emit (a, BPF_ALU64_IMM (BPF_RSH, BPF_REG_3, 2));
  asm_emit (a, BPF_ALU64_IMM (BPF_AND, BPF_REG_3, 1));
  asm_emit (a, BPF_ALU64_REG (BPF_AND, BPF_REG_0, BPF_REG_3));
  asm_emit (a, BPF_EXIT_INSN ());

  asm_label (a, L_NEXT);
  asm_emit (a, BPF_ALU64_IMM (BPF_ADD, BPF_REG_1, sizeof (struct dev_rule)));
  asm_emit (a, BPF_ALU64_IMM (BPF_ADD, BPF_REG_2, 1));
  asm_jump (a, BPF_JMP_IMM (BPF_JLT, BPF_REG_2, CRUN_DEV_MAX_RULES, 0), L_LOOP);

  asm_emit (a, BPF_MOV64_IMM (BPF_REG_0, 0));
  asm_emit (a, BPF_EXIT_INSN ());

  asm_resolve (a);

  if (a->error)
    return crun_make_error (err, 0, "internal error: cannot assemble the eBPF device program");

  return 0;
}

static int
dev_get_obj_info (int fd, void *info, size_t info_len, libcrun_error_t *err)
{
  union bpf_attr attr;
  int ret;

  memset (&attr, 0, sizeof (attr));
  attr.info.bpf_fd = fd;
  attr.info.info = ptr_to_u64 (info);
  attr.info.info_len = info_len;

  ret = bpf (BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof (attr));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "bpf get info");
  return 0;
}

/* Find the map with the rules used by PROG_FD.  Return 1 if PROG_FD is not a crun device program, or if it does not use
   the expected map.  */
static int
dev_find_storage_map (int prog_fd, int *map_fd, libcrun_error_t *err)
{
  struct bpf_prog_info info;
  uint32_t map_ids[16] = {};
  uint32_t i;
  int ret;

  *map_fd = -1;

  memset (&info, 0, sizeof (info));
  info.nr_map_ids = sizeof (map_ids) / sizeof (map_ids[0]);
  info.map_ids = ptr_to_u64 (map_ids);

  ret = dev_get_obj_info (prog_fd, &info, sizeof (info), err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (info.type != BPF_PROG_TYPE_CGROUP_DEVICE || strcmp (info.name, CRUN_DEV_PROG_NAME) != 0)
    return 1;

  for (i = 0; i < info.nr_map_ids && i < sizeof (map_ids) / sizeof (map_ids[0]); i++)
    {
      cleanup_close int fd = -1;
      struct bpf_map_info map_info;
      union bpf_attr attr;

      memset (&attr, 0, sizeof (attr));
      attr.map_id = map_ids[i];
      fd = bpf (BPF_MAP_GET_FD_BY_ID, &attr, sizeof (attr));
      if (UNLIKELY (fd < 0))
        {
          /* The map was released in the meantime.  */
          if (errno == ENOENT)
            continue;
          return crun_make_error (err, errno, "cannot open eBPF map");
        }

      memset (&map_info, 0, sizeof (map_info));
      ret = dev_get_obj_info (fd, &map_info, sizeof (map_info), err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (map_info.type == BPF_MAP_TYPE_CGROUP_STORAGE && map_info.key_size == sizeof (struct bpf_cgroup_storage_key)
          && map_info.value_size == sizeof (struct dev_rules) && strcmp (map_info.name, CRUN_DEV_MAP_NAME) == 0)
        {
          *map_fd = get_and_reset (&fd);
          return 0;
        }
    }

  return 1;
}

/* The id of a cgroup is the 64 bits id of its kernfs node, which is also its file handle.  The inode number is the same
   value only on a 64 bits kernel since Linux 5.5.  */
static int
dev_get_cgroup_id (int cgroup_fd, uint64_t *id, libcrun_error_t *err)
{
  uint64_t buffer[(sizeof (struct file_handle) + sizeof (uint64_t)) / sizeof (uint64_t) + 1];
  struct file_handle *fh = (struct file_handle *) buffer;
  struct stat st;
  int mount_id;
  int ret;

  memset (buffer, 0, sizeof (buffer));
  fh->handle_bytes = sizeof (uint64_t);
  ret = name_to_handle_at (cgroup_fd, "", fh, &mount_id, AT_EMPTY_PATH);
  if (ret == 0 && fh->handle_bytes == sizeof (uint64_t))
    {
      memcpy (id, fh->f_handle, sizeof (uint64_t));
      return 0;
    }

  ret = fstat (cgroup_fd, &st);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fstat cgroup");

  *id = st.st_ino;
  return 0;
}

/* The key of the rules of the cgroup CGROUP_FD in the map.  */
static int
dev_storage_key (int cgroup_fd, struct bpf_cgroup_storage_key *key, libcrun_error_t *err)
{
  uint64_t cgroup_id = 0;
  int ret;

  ret = dev_get_cgroup_id (cgroup_fd, &cgroup_id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  memset (key, 0, sizeof (*key));
  key->cgroup_inode_id = cgroup_id;
  key->attach_type = BPF_CGROUP_DEVICE;
  return 0;
}

/* Replace the rules of the cgroup CGROUP_FD in the map.  The kernel swaps the value, so the program sees either the
   old or the new rules.  */
static int
dev_write_table (int map_fd, int cgroup_fd, const struct dev_rules *table, libcrun_error_t *err)
{
  struct bpf_cgroup_storage_key key;
  union bpf_attr attr;
  int ret;

  ret = dev_storage_key (cgroup_fd, &key, err);
  if (UNLIKELY (ret < 0))
    return ret;

  memset (&attr, 0, sizeof (attr));
  attr.map_fd = map_fd;
  attr.key = ptr_to_u64 (&key);
  attr.value = ptr_to_u64 (table);
  ret = bpf (BPF_MAP_UPDATE_ELEM, &attr, sizeof (attr));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "bpf set device rules");
  return 0;
}

static int
dev_read_table (int map_fd, int cgroup_fd, struct dev_rules *table, libcrun_error_t *err)
{
  struct bpf_cgroup_storage_key key;
  union bpf_attr attr;
  int ret;

  ret = dev_storage_key (cgroup_fd, &key, err);
  if (UNLIKELY (ret < 0))
    return ret;

  memset (&attr, 0, sizeof (attr));
  attr.map_fd = map_fd;
  attr.key = ptr_to_u64 (&key);
  attr.value = ptr_to_u64 (table);
  ret = bpf (BPF_MAP_LOOKUP_ELEM, &attr, sizeof (attr));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "bpf read device rules");
  return 0;
}

static size_t
dev_rules_count (const struct dev_rules *table)
{
  size_t n;

  for (n = 0; n < CRUN_DEV_MAX_RULES; n++)
    if (! (table->rules[n].flags & DEV_RULE_VALID))
      break;
  return n;
}

/* Insert the rule DEV in front of the rules of the user in TABLE, the first match wins.  The rules of the user follow
   the default devices.  An identical rule is moved instead of being added again.  */
static int
dev_rules_insert (struct dev_rules *table, runtime_spec_schema_defs_linux_device_cgroup *dev, libcrun_error_t *err)
{
  cleanup_free struct dev_rules *built = NULL;
  cleanup_free struct dev_rules *out = NULL;
  struct dev_rules_builder b;
  size_t i, n_default, n;
  const struct dev_rule *rule;
  int ret;

  /* The default devices followed by DEV.  */
  built = xmalloc0 (sizeof (*built));
  ret = dev_rules_build (built, &dev, 1, err);
  if (UNLIKELY (ret < 0))
    return ret;

  n_default = dev_rules_count (built) - 1;
  rule = &built->rules[n_default];

  n = dev_rules_count (table);
  if (n < n_default || memcmp (table->rules, built->rules, n_default * sizeof (struct dev_rule)) != 0)
    return crun_make_error (err, 0, "the device rules of the cgroup do not start with the default devices");

  out = xmalloc0 (sizeof (*out));
  memcpy (out->rules, built->rules, n_default * sizeof (struct dev_rule));
  b.table = out;
  b.n = n_default;
  b.wildcard = false;

  ret = dev_rules_append_record (&b, rule, err);
  if (UNLIKELY (ret < 0))
    return ret;

  for (i = n_default; i < n; i++)
    {
      if (memcmp (&table->rules[i], rule, sizeof (*rule)) == 0)
        continue;

      ret = dev_rules_append_record (&b, &table->rules[i], err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  memcpy (table, out, sizeof (*table));
  return 0;
}

/* Create the map for the rules in MAP_FD, that is owned by the caller, and load the program that reads them from it.  */
static int
dev_load_program (int *map_fd, libcrun_error_t *err)
{
  cleanup_free struct asm_ctx *a = NULL;
  int ret;

  *map_fd = dev_create_storage_map (err);
  if (UNLIKELY (*map_fd < 0))
    return *map_fd;

  a = xmalloc (sizeof (*a));
  ret = dev_build_program (a, *map_fd, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return ebpf_prog_load (a->insns, a->n, CRUN_DEV_PROG_NAME, err);
}

/* Find the map with the rules of the crun device program among the programs PROGS.  Return 1 if there is no such
   program.  */
static int
dev_find_cgroup_map (const uint32_t *progs, size_t n_progs, int *map_fd, libcrun_error_t *err)
{
  size_t i;
  int ret;

  *map_fd = -1;

  for (i = 0; i < n_progs; i++)
    {
      cleanup_close int fd = -1;
      union bpf_attr attr;

      memset (&attr, 0, sizeof (attr));
      attr.prog_id = progs[i];
      fd = bpf (BPF_PROG_GET_FD_BY_ID, &attr, sizeof (attr));
      if (UNLIKELY (fd < 0))
        {
          /* The program was detached in the meantime.  */
          if (errno == ENOENT)
            continue;
          return crun_make_error (err, errno, "cannot open existing eBPF program");
        }

      ret = dev_find_storage_map (fd, map_fd, err);
      if (ret <= 0)
        return ret;
    }

  return 1;
}

/* Replace the rules of the crun device program, among the programs PROGS attached to CGROUP_FD.  Return 1 if there is no
   such program.  */
static int
dev_update_cgroup (const struct dev_rules *table, int cgroup_fd, const uint32_t *progs, size_t n_progs,
                   libcrun_error_t *err)
{
  cleanup_close int map_fd = -1;
  int ret;

  ret = dev_find_cgroup_map (progs, n_progs, &map_fd, err);
  if (ret != 0)
    return ret;

  return dev_write_table (map_fd, cgroup_fd, table, err);
}

/* The name of the pinned program depends on its instructions, so that programs that differ are never mixed.  */
static uint64_t
dev_program_hash (const struct asm_ctx *a)
{
  const unsigned char *p = (const unsigned char *) a->insns;
  size_t i, len = a->n * sizeof (a->insns[0]);
  uint64_t hash = 0xcbf29ce484222325ULL;

  for (i = 0; i < len; i++)
    {
      hash ^= p[i];
      hash *= 0x100000001b3ULL;
    }
  return hash;
}

/* Get the program shared by all the containers, and load and pin it if it is not there yet.  Return 1 if the kernel
   does not support the program.  */
static int
dev_get_shared_program (int *prog_fd_out, int *map_fd_out, char **path_out, libcrun_error_t *err)
{
  cleanup_free struct asm_ctx *a = NULL;
  libcrun_error_t tmp_err = NULL;
  cleanup_close int map_fd = -1;
  cleanup_close int prog_fd = -1;
  union bpf_attr attr;
  char path[128];
  int ret;

  /* The map is not part of the instructions that are hashed.  */
  a = xmalloc (sizeof (*a));
  ret = dev_build_program (a, 0, err);
  if (UNLIKELY (ret < 0))
    return ret;

  snprintf (path, sizeof (path), CRUN_BPF_DIR "/devices-%016" PRIx64, dev_program_hash (a));

  ret = mkdir (CRUN_BPF_DIR, 0700);
  if (UNLIKELY (ret < 0 && errno != EEXIST))
    return crun_make_error (err, errno, "mkdir " CRUN_BPF_DIR);

  memset (&attr, 0, sizeof (attr));
  attr.pathname = ptr_to_u64 (path);
  prog_fd = bpf (BPF_OBJ_GET, &attr, sizeof (attr));
  if (prog_fd < 0 && errno != ENOENT)
    return crun_make_error (err, errno, "bpf get `%s`", path);

  if (prog_fd < 0)
    {
      prog_fd = dev_load_program (&map_fd, &tmp_err);
      if (prog_fd < 0)
        {
          crun_error_release (&tmp_err);
          return 1;
        }

      ret = ebpf_pin (prog_fd, path, err);
      if (ret < 0)
        {
          /* Another process created it in the meantime.  */
          if (crun_error_get_errno (err) != EEXIST)
            return ret;
          crun_error_release (err);

          close (get_and_reset (&prog_fd));
          close (get_and_reset (&map_fd));

          memset (&attr, 0, sizeof (attr));
          attr.pathname = ptr_to_u64 (path);
          prog_fd = bpf (BPF_OBJ_GET, &attr, sizeof (attr));
          if (UNLIKELY (prog_fd < 0))
            return crun_make_error (err, errno, "bpf get `%s`", path);
        }
    }

  if (map_fd < 0)
    {
      /* The file was not created by this process, check that it is the expected program.  */
      ret = dev_find_storage_map (prog_fd, &map_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
      if (ret > 0)
        return crun_make_error (err, 0, "the eBPF object `%s` is not the crun device filter", path);
    }

  *prog_fd_out = get_and_reset (&prog_fd);
  *map_fd_out = get_and_reset (&map_fd);
  if (path_out)
    *path_out = xstrdup (path);
  return 0;
}

#endif

int
libcrun_ebpf_devices_set (runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len, int cgroup_fd,
                          libcrun_error_t *err)
{
#ifndef HAVE_EBPF
  (void) devs;
  (void) devs_len;
  (void) cgroup_fd;
  (void) err;
  return 1;
#else
  cleanup_free struct dev_rules *table = NULL;
  cleanup_free uint32_t *progs = NULL;
  libcrun_error_t tmp_err = NULL;
  cleanup_close int map_fd = -1;
  cleanup_close int prog_fd = -1;
  size_t n_progs = 0;
  int ret;

  table = xmalloc0 (sizeof (*table));
  ret = dev_rules_build (table, devs, devs_len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* If the programs cannot be read, the caller decides whether the filter is needed.  */
  ret = read_all_progs (cgroup_fd, &progs, &n_progs, &tmp_err);
  if (UNLIKELY (ret < 0))
    {
      crun_error_release (&tmp_err);
      return 1;
    }

  ret = dev_update_cgroup (table, cgroup_fd, progs, n_progs, err);
  if (ret <= 0)
    return ret;

  /* Another program is attached, e.g. the one generated by an older version.  The new program would deny every device
     until its rules are written, so keep using the generated program, that is replaced atomically.  */
  if (n_progs > 0)
    return 1;

  /* The kernel may not support the program, let the caller use the fallback.  */
  ret = dev_get_shared_program (&prog_fd, &map_fd, NULL, &tmp_err);
  if (ret > 0)
    return 1;
  if (UNLIKELY (ret < 0))
    {
      /* The program cannot be pinned, e.g. bpffs is not mounted, load it for this cgroup.  */
      crun_error_release (&tmp_err);
      prog_fd = dev_load_program (&map_fd, &tmp_err);
      if (prog_fd < 0)
        {
          crun_error_release (&tmp_err);
          return 1;
        }
    }

  ret = ebpf_attach_program (prog_fd, cgroup_fd, &tmp_err);
  if (UNLIKELY (ret < 0))
    {
      crun_error_release (&tmp_err);
      return 1;
    }

  ret = dev_write_table (map_fd, cgroup_fd, table, err);
  if (UNLIKELY (ret < 0))
    {
      union bpf_attr attr;

      /* Without its rules the program denies every device, do not leave it attached.  */
      memset (&attr, 0, sizeof (attr));
      attr.attach_type = BPF_CGROUP_DEVICE;
      attr.target_fd = cgroup_fd;
      attr.attach_bpf_fd = prog_fd;
      if (UNLIKELY (bpf (BPF_PROG_DETACH, &attr, sizeof (attr)) < 0))
        return crun_error_wrap (err, "cannot detach the eBPF device filter (%s)", strerror (errno));
      return ret;
    }

  return 0;
#endif
}

int
libcrun_ebpf_devices_update (runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len, int cgroup_fd,
                             libcrun_error_t *err)
{
#ifndef HAVE_EBPF
  (void) devs;
  (void) devs_len;
  (void) cgroup_fd;
  (void) err;
  return 1;
#else
  cleanup_free struct dev_rules *table = NULL;
  cleanup_free uint32_t *progs = NULL;
  size_t n_progs = 0;
  int ret;

  table = xmalloc0 (sizeof (*table));
  ret = dev_rules_build (table, devs, devs_len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = read_all_progs (cgroup_fd, &progs, &n_progs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return dev_update_cgroup (table, cgroup_fd, progs, n_progs, err);
#endif
}

int
libcrun_ebpf_devices_add (runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len, int cgroup_fd,
                          libcrun_error_t *err)
{
#ifndef HAVE_EBPF
  (void) devs;
  (void) devs_len;
  (void) cgroup_fd;
  (void) err;
  return 1;
#else
  cleanup_free struct dev_rules *current = NULL;
  cleanup_free struct dev_rules *table = NULL;
  cleanup_free uint32_t *progs = NULL;
  cleanup_close int map_fd = -1;
  size_t i, n_progs = 0;
  int ret;

  ret = read_all_progs (cgroup_fd, &progs, &n_progs, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = dev_find_cgroup_map (progs, n_progs, &map_fd, err);
  if (ret != 0)
    return ret;

  current = xmalloc0 (sizeof (*current));
  ret = dev_read_table (map_fd, cgroup_fd, current, err);
  if (UNLIKELY (ret < 0))
    return ret;

  table = xmalloc (sizeof (*table));
  memcpy (table, current, sizeof (*table));

  for (i = 0; i < devs_len; i++)
    {
      ret = dev_rules_insert (table, devs[i], err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (memcmp (table, current, sizeof (*table)) == 0)
    return 0;

  return dev_write_table (map_fd, cgroup_fd, table, err);
#endif
}

int
libcrun_ebpf_devices_pin (runtime_spec_schema_defs_linux_device_cgroup **devs, size_t devs_len, char **path_out,
                          libcrun_error_t *err)
{
#ifndef HAVE_EBPF
  (void) devs;
  (void) devs_len;
  (void) path_out;
  (void) err;
  return 1;
#else
  cleanup_free struct dev_rules *table = NULL;
  cleanup_close int map_fd = -1;
  cleanup_close int prog_fd = -1;
  int ret;

  /* The rules are set later on the cgroup, but a list that does not fit is an error.  */
  table = xmalloc0 (sizeof (*table));
  ret = dev_rules_build (table, devs, devs_len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return dev_get_shared_program (&prog_fd, &map_fd, path_out, err);
#endif
}
