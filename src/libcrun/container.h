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

#ifndef CONTAINER_H
# define CONTAINER_H

# include <config.h>
# include <oci_runtime_spec.h>
# include "error.h"

struct libcrun_context_s
{
  char *state_root;
  const char *id;
  const char *bundle;
  const char *console_socket;
  const char *pid_file;
  char *notify_socket;
  int preserve_fds;

  crun_output_handler output_handler;
  void *output_handler_arg;

  int fifo_exec_wait_fd;

  bool systemd_cgroup;
  bool detach;
  bool no_subreaper;
  bool no_new_keyring;
};

enum
  {
    LIBCRUN_RUN_OPTIONS_PREFORK = 1 << 0,
  };

struct libcrun_container_s
{
  /* Container parsed from the runtime json file.  */
  oci_container *container_def;

  uid_t host_uid;
  gid_t host_gid;

  uid_t container_uid;
  gid_t container_gid;

  void *private_data;
  struct libcrun_context_s *context;
};

typedef struct libcrun_container_s libcrun_container_t;
typedef struct libcrun_context_s libcrun_context_t;

libcrun_container_t *libcrun_container_load_from_file (const char *path, libcrun_error_t *err);

libcrun_container_t *libcrun_container_load_from_memory (const char *json, libcrun_error_t *err);

int libcrun_container_run (libcrun_context_t *context, libcrun_container_t *container, unsigned int options, libcrun_error_t *error);

int libcrun_container_delete (libcrun_context_t *context, oci_container *def, const char *id, bool force, libcrun_error_t *err);

int libcrun_container_kill (libcrun_context_t *context, const char *id, int signal, libcrun_error_t *err);

int libcrun_container_create (libcrun_context_t *context, libcrun_container_t *container, libcrun_error_t *err);

int libcrun_container_start (libcrun_context_t *context, const char *id, libcrun_error_t *err);

int libcrun_container_state (libcrun_context_t *context, const char *id, FILE *out, libcrun_error_t *err);

int libcrun_container_exec (libcrun_context_t *context, const char *id, oci_container_process *process, libcrun_error_t *err);

int libcrun_container_exec_process_file (libcrun_context_t *context, const char *id, const char *path, libcrun_error_t *err);

int libcrun_container_update (libcrun_context_t *context, const char *id, const char *content, size_t len, libcrun_error_t *err);

int libcrun_container_spec (bool root, FILE *out, libcrun_error_t *err);

int libcrun_container_pause (libcrun_context_t *context, const char *id, libcrun_error_t *err);

int libcrun_container_unpause (libcrun_context_t *context, const char *id, libcrun_error_t *err);

#endif
