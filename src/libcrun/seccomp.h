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
#ifndef SECCOMP_H
#define SECCOMP_H
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "error.h"
#include <errno.h>
#include <argp.h>
#include <ocispec/runtime_spec_schema_config_schema.h>
#include "container.h"

enum
{
  LIBCRUN_SECCOMP_FAIL_UNKNOWN_SYSCALL = 1 << 0,
};

typedef char seccomp_checksum_t[65];

struct libcrun_seccomp_gen_ctx_s
{
  libcrun_container_t *container;
  seccomp_checksum_t checksum;
  unsigned int options;
  bool create;

  /* Not owned here, it is the caller responsibility to close it.  */
  int fd;
};

static inline void libcrun_seccomp_gen_ctx_init (struct libcrun_seccomp_gen_ctx_s *ctx, libcrun_container_t *container, bool create, unsigned int seccomp_gen_options)
{
  memset (ctx, 0, sizeof (*ctx));
  ctx->create = create;
  ctx->container = container;
  ctx->options = seccomp_gen_options;
}

int libcrun_generate_seccomp (struct libcrun_seccomp_gen_ctx_s *gen_ctx, libcrun_error_t *err);
int libcrun_copy_seccomp (struct libcrun_seccomp_gen_ctx_s *gen_ctx, const char *b64_bpf, libcrun_error_t *err);
int libcrun_apply_seccomp (int infd, int listener_receiver_fd, const char *receiver_fd_payload,
                           size_t receiver_fd_payload_len, char **flags, size_t flags_len, libcrun_error_t *err);
int libcrun_open_seccomp_bpf (struct libcrun_seccomp_gen_ctx_s *ctx, int *fd, libcrun_error_t *err);

#endif
