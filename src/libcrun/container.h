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

#ifndef CONTAINER_H
#define CONTAINER_H

#include <config.h>
#include <runtime_spec_schema_config_schema.h>
#include "error.h"

struct libcrun_context_s
{
  const char *state_root;
  const char *id;
  const char *bundle;
  const char *config_file;
  const char *config_file_content;
  const char *console_socket;
  const char *pid_file;
  const char *notify_socket;
  const char *handler;
  int preserve_fds;
  // For some use-cases we need differentiation between preserve_fds and listen_fds.
  // Following context variable makes sure we get exact value of listen_fds irrespective of preserve_fds.
  int listen_fds;

  crun_output_handler output_handler;
  void *output_handler_arg;

  int fifo_exec_wait_fd;

  bool systemd_cgroup;
  bool detach;
  bool no_subreaper;
  bool no_new_keyring;
  bool force_no_cgroup;
  bool no_pivot;

  int (*exec_func) (void *container, void *arg, const char *pathname, char *const argv[]);
  void *exec_func_arg;
};

enum
{
  LIBCRUN_RUN_OPTIONS_PREFORK = 1 << 0,
};

struct libcrun_container_s
{
  /* Container parsed from the runtime json file.  */
  runtime_spec_schema_config_schema *container_def;

  uid_t host_uid;
  gid_t host_gid;

  uid_t container_uid;
  gid_t container_gid;

  bool use_intermediate_userns;

  void *private_data;
  struct libcrun_context_s *context;
};

struct libcrun_container_status_s;
typedef struct libcrun_container_status_s libcrun_container_status_t;

typedef struct libcrun_container_s libcrun_container_t;
typedef struct libcrun_context_s libcrun_context_t;

struct libcrun_checkpoint_restore_s
{
  char *image_path;
  char *work_path;
  bool leave_running;
  bool tcp_established;
  bool shell_job;
  bool ext_unix_sk;
  bool detach;
  const char *console_socket;
};
typedef struct libcrun_checkpoint_restore_s libcrun_checkpoint_restore_t;

LIBCRUN_PUBLIC libcrun_container_t *libcrun_container_load_from_file (const char *path, libcrun_error_t *err);

LIBCRUN_PUBLIC libcrun_container_t *libcrun_container_load_from_memory (const char *json, libcrun_error_t *err);

LIBCRUN_PUBLIC void libcrun_container_free (libcrun_container_t *);

LIBCRUN_PUBLIC int libcrun_container_run (libcrun_context_t *context, libcrun_container_t *container,
                                          unsigned int options, libcrun_error_t *error);

LIBCRUN_PUBLIC int libcrun_container_delete (libcrun_context_t *context, runtime_spec_schema_config_schema *def,
                                             const char *id, bool force, libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_kill (libcrun_context_t *context, const char *id, int signal,
                                           libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_kill_all (libcrun_context_t *context, const char *id, int signal,
                                               libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_create (libcrun_context_t *context, libcrun_container_t *container,
                                             unsigned int options, libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_start (libcrun_context_t *context, const char *id, libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_state (libcrun_context_t *context, const char *id, FILE *out,
                                            libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_get_container_state_string (const char *id, libcrun_container_status_t *status,
                                                       const char *state_root, const char **container_status,
                                                       int *running, libcrun_error_t *err);

struct libcrun_container_exec_options_s
{
  size_t struct_size;
  runtime_spec_schema_config_schema_process *process;
  const char *path;
};

LIBCRUN_PUBLIC int libcrun_container_exec_with_options (libcrun_context_t *context, const char *id,
                                                        struct libcrun_container_exec_options_s *opts,
                                                        libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_exec (libcrun_context_t *context, const char *id,
                                           runtime_spec_schema_config_schema_process *process, libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_exec_process_file (libcrun_context_t *context, const char *id, const char *path,
                                                        libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_update (libcrun_context_t *context, const char *id, const char *content,
                                             size_t len, libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_update_from_file (libcrun_context_t *context, const char *id, const char *file,
                                                       libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_spec (bool root, FILE *out, libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_pause (libcrun_context_t *context, const char *id, libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_unpause (libcrun_context_t *context, const char *id, libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_checkpoint (libcrun_context_t *context, const char *id,
                                                 libcrun_checkpoint_restore_t *cr_options, libcrun_error_t *err);

LIBCRUN_PUBLIC int libcrun_container_restore (libcrun_context_t *context, const char *id,
                                              libcrun_checkpoint_restore_t *cr_options, libcrun_error_t *err);

// Not part of the public API, just a method in container.c we need to access from linux.c
void get_root_in_the_userns (runtime_spec_schema_config_schema *def, uid_t host_uid, gid_t host_gid,
                             uid_t *uid, gid_t *gid);

static inline void
cleanup_containerp (libcrun_container_t **c)
{
  libcrun_container_t *container = *c;
  libcrun_container_free (container);
}

#define cleanup_container __attribute__ ((cleanup (cleanup_containerp)))

#endif
