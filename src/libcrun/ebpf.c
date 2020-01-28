/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include "ebpf.h"
#include "utils.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#ifdef HAVE_EBPF
# include <linux/bpf.h>

# ifndef HAVE_BPF
static int
syscall_bpf (int cmd, union bpf_attr *attr, unsigned int size)
{
  return (int) syscall (__NR_bpf, cmd, attr, size);
}
#  define bpf syscall_bpf
# endif

#endif

enum {
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

# define BPF_ALU32_IMM(OP, DST, IMM)            \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU | BPF_OP(OP) | BPF_K,      \
      .dst_reg = DST,                           \
      .src_reg = 0,                             \
      .off   = 0,                               \
      .imm   = IMM })

# define BPF_LDX_MEM(SIZE, DST, SRC, OFF)               \
  ((struct bpf_insn) {                                  \
    .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,        \
      .dst_reg = DST,                                   \
      .src_reg = SRC,                                   \
      .off   = OFF,                                     \
      .imm   = 0 })

# define BPF_MOV64_REG(DST, SRC)                \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_X,       \
      .dst_reg = DST,                           \
      .src_reg = SRC,                           \
      .off   = 0,                               \
      .imm   = 0 })

# define BPF_JMP_A(OFF)                         \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_JA,                  \
      .dst_reg = 0,                             \
      .src_reg = 0,                             \
      .off   = OFF,                             \
      .imm   = 0 })

# define BPF_JMP_IMM(OP, DST, IMM, OFF)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_K,      \
      .dst_reg = DST,                           \
      .src_reg = 0,                             \
      .off   = OFF,                             \
      .imm   = IMM })

# define BPF_MOV64_IMM(DST, IMM)                \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_K,       \
      .dst_reg = DST,                           \
      .src_reg = 0,                             \
      .off   = 0,                               \
      .imm   = IMM })

# define BPF_MOV32_REG(DST, SRC)                \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU | BPF_MOV | BPF_X,         \
      .dst_reg = DST,                           \
      .src_reg = SRC,                           \
      .off   = 0,                               \
      .imm   = 0 })

# define BPF_EXIT_INSN()                        \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_EXIT,                \
      .dst_reg = 0,                             \
      .src_reg = 0,                             \
      .off   = 0,                               \
      .imm   = 0 })
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
                                BPF_LDX_MEM (BPF_H, BPF_REG_2, BPF_REG_1, 0),

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
bpf_program_append_dev (struct bpf_program *program, const char *access, char type, int major, int minor, bool accept, libcrun_error_t *err arg_unused)
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

  if (program->private & HAS_WILDCARD)
    return 0;

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
    if ((request.access & device.access) == 0)
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
      struct bpf_insn bpf_i[] = {
                             BPF_JMP_IMM (BPF_JNE, BPF_REG_2, bpf_type, number_instructions)
      };
      number_instructions--;
      program = bpf_program_append (program, bpf_i, sizeof (i));
    }
  if (has_access)
    {
      struct bpf_insn bpf_i[] = {
                             BPF_MOV32_REG (BPF_REG_1, BPF_REG_3),
                             BPF_ALU32_IMM (BPF_AND, BPF_REG_1, bpf_access),
                             BPF_JMP_IMM (BPF_JEQ, BPF_REG_1, 0, number_instructions - 2),
      };
      number_instructions -= 3;
      program = bpf_program_append (program, bpf_i, sizeof (i));
    }
  if (has_major)
    {
      struct bpf_insn bpf_i[] = {
                             BPF_JMP_IMM (BPF_JNE, BPF_REG_4, major, number_instructions)
      };
      number_instructions--;
      program = bpf_program_append (program, bpf_i, sizeof (i));
    }
  if (has_minor)
    {
      struct bpf_insn bpf_i[] = {
                             BPF_JMP_IMM (BPF_JNE, BPF_REG_5, minor, number_instructions)
      };
      number_instructions--;
      program = bpf_program_append (program, bpf_i, sizeof (i));
    }

  if (has_type == 0 && has_access == 0 && has_major == 0 && has_minor == 0)
    program->private |= HAS_WILDCARD;

  program = bpf_program_append (program, accept_block, sizeof (accept_block));
#endif
  return program;
}

struct bpf_program *
bpf_program_complete_dev (struct bpf_program *program, libcrun_error_t *err arg_unused)
{
#ifdef HAVE_EBPF
  struct bpf_insn bpf_i[] = {
                         BPF_MOV64_IMM (BPF_REG_0, 0),
                         BPF_EXIT_INSN (),
  };

  if (program->private & HAS_WILDCARD)
    return program;

  program = bpf_program_append (program, &bpf_i, sizeof (i));
#endif
  return program;
}

int
libcrun_ebpf_load (struct bpf_program *program, int dirfd, const char *pin, libcrun_error_t *err)
{
#ifndef HAVE_EBPF
  return crun_make_error (err, 0, "eBPF not supported");
#else
  int fd, ret;
  union bpf_attr attr;
  struct rlimit limit;

  limit.rlim_cur = RLIM_INFINITY;
  limit.rlim_max = RLIM_INFINITY;
  ret = setrlimit (RLIMIT_MEMLOCK, &limit);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "setrlimit (RLIM_MEMLOCK)");

  memset (&attr, 0, sizeof (attr));
  attr.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
  attr.insns = (uint64_t) program->program;
  attr.insn_cnt = bpf_program_instructions (program);
  attr.license = (uint64_t) "GPL";

  /* First try without log.  */
  fd = bpf (BPF_PROG_LOAD, &attr, sizeof (attr));
  if (fd < 0)
    {
      const size_t log_size = 8192;
      cleanup_free char *log = xmalloc (log_size);

      log[0] = '\0';
      attr.log_level = 1;
      attr.log_buf = (uint64_t) log;
      attr.log_size = log_size;

      fd = bpf (BPF_PROG_LOAD, &attr, sizeof (attr));
      if (fd < 0)
        return crun_make_error (err, errno, "bpf create %s", log);
    }

  memset (&attr, 0, sizeof (attr));
  attr.attach_type = BPF_CGROUP_DEVICE;
  attr.target_fd = dirfd;
  attr.attach_bpf_fd = fd;
  attr.attach_flags = BPF_F_ALLOW_MULTI;

  ret = bpf (BPF_PROG_ATTACH, &attr, sizeof (attr));
  if (ret < 0)
    return crun_make_error (err, errno, "bpf attach");

  /* Optionally pin the program to the specified path.  */
  if (pin)
    {
      memset (&attr, 0, sizeof (attr));
      attr.pathname = (uint64_t) pin;
      attr.bpf_fd = fd;
      ret = bpf (BPF_OBJ_PIN, &attr, sizeof (attr));
      if (ret < 0)
        return crun_make_error (err, errno, "bpf pin to %s", pin);
    }

  return fd;
#endif
}
