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
#ifndef EBPF_H
#define EBPF_H

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include "error.h"
#include <errno.h>
#include <argp.h>
#include <ocispec/runtime_spec_schema_config_schema.h>
#include "container.h"

#define SYS_FS_BPF "/sys/fs/bpf"
#define CRUN_BPF_DIR SYS_FS_BPF "/crun"

struct bpf_program;

struct bpf_program *bpf_program_new (size_t size);
struct bpf_program *bpf_program_append (struct bpf_program *p, void *data, size_t size);

struct bpf_program *bpf_program_init_dev (struct bpf_program *program, libcrun_error_t *err);
struct bpf_program *bpf_program_append_dev (struct bpf_program *program, const char *access, char type, int major,
                                            int minor, bool accept, libcrun_error_t *err);
struct bpf_program *bpf_program_complete_dev (struct bpf_program *program, libcrun_error_t *err);

int libcrun_ebpf_load (struct bpf_program *program, int dirfd, const char *pin, libcrun_error_t *err);

#endif
