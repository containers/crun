/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2026 Giuseppe Scrivano <giuseppe@scrivano.org>
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

/*
 * Public API for libcrun.  This is the only header external consumers should
 * include:
 *
 *   #include <libcrun.h>
 *
 * All handles are opaque; OCI data crosses the boundary as JSON.  Functions
 * return int (0/positive on success, negative on error) and take a trailing
 * libcrun_error_t *err; loaders return a handle or NULL.  On error *err is set
 * and the caller releases it with libcrun_error_release.
 */

#ifndef LIBCRUN_H
#define LIBCRUN_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __GNUC__
#  define LIBCRUN_PRINTF(a, b) __attribute__ ((format (printf, a, b)))
#  define LIBCRUN_NORETURN __attribute__ ((noreturn))
#else
#  define LIBCRUN_PRINTF(a, b)
#  define LIBCRUN_NORETURN
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles.  */
typedef struct libcrun_error_s *libcrun_error_t;
typedef struct libcrun_context_s libcrun_context_t;
typedef struct libcrun_container_s libcrun_container_t;
typedef struct libcrun_status_s libcrun_status_t;
typedef struct libcrun_container_list_s libcrun_container_list_t;
typedef struct libcrun_container_iter_s libcrun_container_iter_t;

enum
{
  LIBCRUN_RUN_OPTIONS_PREFORK = 1 << 0,
  LIBCRUN_RUN_OPTIONS_KEEP = 1 << 1,
};

enum
{
  LIBCRUN_CREATE_OPTIONS_PREFORK = 1 << 0,
};

enum
{
  LIBCRUN_VERBOSITY_ERROR = 0,
  LIBCRUN_VERBOSITY_WARNING,
  LIBCRUN_VERBOSITY_DEBUG,
};

typedef enum
{
  LIBCRUN_CONTAINER_STATUS_CREATING = 0,
  LIBCRUN_CONTAINER_STATUS_CREATED,
  LIBCRUN_CONTAINER_STATUS_RUNNING,
  LIBCRUN_CONTAINER_STATUS_STOPPED,
  LIBCRUN_CONTAINER_STATUS_PAUSED,
} libcrun_container_state_t;

typedef void (*libcrun_output_handler) (int errno_, const char *msg, int verbosity, void *arg);

/* Error handling.  */
int libcrun_error_get_status (libcrun_error_t err);
const char *libcrun_error_get_message (libcrun_error_t err);
int libcrun_error_release (libcrun_error_t *err);

/* Create an error object; returns a negative value derived from status.  */
int libcrun_make_error (libcrun_error_t *err, int status, const char *fmt, ...) LIBCRUN_PRINTF (3, 4);

/* Report *err through the configured log handler and release it.  */
void libcrun_error_report_and_release (libcrun_error_t *err);

/* Report the error and terminate the process.  */
void libcrun_fail_with_error (int errno_, const char *fmt, ...) LIBCRUN_NORETURN LIBCRUN_PRINTF (2, 3);

/* Logging.  */
void libcrun_set_verbosity (int verbosity);
int libcrun_get_verbosity (void);
int libcrun_set_log_format (const char *format, libcrun_error_t *err);
void libcrun_debug (const char *fmt, ...) LIBCRUN_PRINTF (1, 2);
void libcrun_warning (const char *fmt, ...) LIBCRUN_PRINTF (1, 2);
void libcrun_error (int errno_, const char *fmt, ...) LIBCRUN_PRINTF (2, 3);

/* Context.  */
libcrun_context_t *libcrun_context_new (const char *id, const char *state_root, libcrun_error_t *err);
void libcrun_context_free (libcrun_context_t *ctx);

void libcrun_context_set_id (libcrun_context_t *ctx, const char *value);
void libcrun_context_set_state_root (libcrun_context_t *ctx, const char *value);
void libcrun_context_set_bundle (libcrun_context_t *ctx, const char *value);
void libcrun_context_set_console_socket (libcrun_context_t *ctx, const char *value);
void libcrun_context_set_pid_file (libcrun_context_t *ctx, const char *value);
void libcrun_context_set_notify_socket (libcrun_context_t *ctx, const char *value);
void libcrun_context_set_handler (libcrun_context_t *ctx, const char *value);
void libcrun_context_set_preserve_fds (libcrun_context_t *ctx, int preserve_fds);
int libcrun_context_get_preserve_fds (libcrun_context_t *ctx);
void libcrun_context_set_listen_fds (libcrun_context_t *ctx, int listen_fds);
void libcrun_context_set_args (libcrun_context_t *ctx, int argc, char **argv);
void libcrun_context_set_systemd_cgroup (libcrun_context_t *ctx, bool value);
void libcrun_context_set_detach (libcrun_context_t *ctx, bool value);
void libcrun_context_set_no_new_keyring (libcrun_context_t *ctx, bool value);
void libcrun_context_set_no_pivot (libcrun_context_t *ctx, bool value);
void libcrun_context_set_force_no_cgroup (libcrun_context_t *ctx, bool value);
void libcrun_context_set_output_handler (libcrun_context_t *ctx, libcrun_output_handler handler, void *arg);
int libcrun_context_init_logging (libcrun_context_t *ctx, const char *log, libcrun_error_t *err);

/* Container object (loaded from JSON, introspected via accessors).  */
libcrun_container_t *libcrun_container_load_from_file (const char *path, libcrun_error_t *err);
libcrun_container_t *libcrun_container_load_from_memory (const char *json, libcrun_error_t *err);
void libcrun_container_free (libcrun_container_t *container);

const char *libcrun_container_get_config_json (libcrun_container_t *container);
const char *libcrun_container_get_annotation (libcrun_container_t *container, const char *key);
uid_t libcrun_container_get_uid (libcrun_container_t *container);
gid_t libcrun_container_get_gid (libcrun_container_t *container);

/* Lifecycle.  */
int libcrun_container_run (libcrun_context_t *ctx, libcrun_container_t *container, unsigned int options,
                           libcrun_error_t *err);
int libcrun_container_create (libcrun_context_t *ctx, libcrun_container_t *container, unsigned int options,
                              libcrun_error_t *err);
int libcrun_container_start (libcrun_context_t *ctx, const char *id, libcrun_error_t *err);
int libcrun_container_delete (libcrun_context_t *ctx, const char *id, bool force, libcrun_error_t *err);
int libcrun_container_kill (libcrun_context_t *ctx, const char *id, const char *signal, libcrun_error_t *err);
int libcrun_container_killall (libcrun_context_t *ctx, const char *id, const char *signal, libcrun_error_t *err);
int libcrun_container_pause (libcrun_context_t *ctx, const char *id, libcrun_error_t *err);
int libcrun_container_unpause (libcrun_context_t *ctx, const char *id, libcrun_error_t *err);
int libcrun_container_update (libcrun_context_t *ctx, const char *id, const char *content, size_t len,
                              libcrun_error_t *err);

/* JSON in, JSON out; caller frees *out with free().  */
int libcrun_container_spec_json (bool root, char **out, libcrun_error_t *err);
int libcrun_container_state_json (libcrun_context_t *ctx, const char *id, char **out, libcrun_error_t *err);

/* Runtime features as an OCI features JSON document; caller frees *out with free().  */
int libcrun_container_get_features_json (libcrun_context_t *ctx, char **out, libcrun_error_t *err);

struct libcrun_exec_options_s
{
  size_t struct_size; /* set to sizeof (struct libcrun_exec_options_s) */
  const char *process_json;
  const char *cgroup;
  bool merge_env; /* merge the container environment with the one in process_json */
};

int libcrun_container_exec_json (libcrun_context_t *ctx, const char *id, const char *process_json,
                                 libcrun_error_t *err);
int libcrun_container_exec_with_options_json (libcrun_context_t *ctx, const char *id,
                                              const struct libcrun_exec_options_s *opts, libcrun_error_t *err);

/* Status.  */
int libcrun_container_status_load (libcrun_context_t *ctx, const char *id, libcrun_status_t **out,
                                   libcrun_error_t *err);
void libcrun_container_status_free (libcrun_status_t *st);

libcrun_container_state_t libcrun_status_get_state (libcrun_status_t *st);
pid_t libcrun_status_get_pid (libcrun_status_t *st);
const char *libcrun_status_get_bundle (libcrun_status_t *st);
const char *libcrun_status_get_rootfs (libcrun_status_t *st);
const char *libcrun_status_get_created (libcrun_status_t *st);
const char *libcrun_status_get_owner (libcrun_status_t *st);
const char *libcrun_status_get_external_descriptors (libcrun_status_t *st);

/* Live status string ("creating"/"created"/"running"/"stopped"/"paused"), obtained by
   probing the container (cgroup/fifo/pid) rather than reading the stored enum.  *out
   points to a static string (do not free).  If running is non-NULL it receives 1 when
   the container has a live process, 0 otherwise.  */
int libcrun_container_get_state_string (libcrun_context_t *ctx, const char *id, const char **out, int *running,
                                        libcrun_error_t *err);

/* Resolve the on-disk state directory for a container (id may be NULL for the state
   root itself); caller frees *out with free().  */
int libcrun_get_state_dir (char **out, const char *state_root, const char *id, libcrun_error_t *err);

/* List containers under the state root.  Obtain a cursor with
   libcrun_container_list_iter and walk it with libcrun_container_iter_next, which
   stores a borrowed container id in *id and returns true until the list is exhausted.  */
int libcrun_container_list (libcrun_context_t *ctx, libcrun_container_list_t **out, libcrun_error_t *err);
libcrun_container_iter_t *libcrun_container_list_iter (libcrun_container_list_t *l);
bool libcrun_container_iter_next (libcrun_container_iter_t *it, const char **id);
void libcrun_container_iter_free (libcrun_container_iter_t *it);
void libcrun_container_list_free (libcrun_container_list_t *l);

/* All containers with their details as a JSON array; caller frees *out with free().  */
int libcrun_container_list_json (libcrun_context_t *ctx, char **out, libcrun_error_t *err);

/* Update the resources of a running container from an OCI resources JSON file.  */
int libcrun_container_update_from_file (libcrun_context_t *ctx, const char *id, const char *file,
                                        libcrun_error_t *err);

/* Update individual resource values.  */
struct libcrun_update_value_s
{
  const char *section;
  const char *name;
  bool numeric;
  const char *value;
};

int libcrun_container_update_from_values (libcrun_context_t *ctx, const char *id,
                                          struct libcrun_update_value_s *values, size_t len,
                                          libcrun_error_t *err);

/* Update the Intel RDT (L3 cache / memory bandwidth) schemata.  */
struct libcrun_intel_rdt_update
{
  const char *l3_cache_schema;
  const char *mem_bw_schema;
  char *const *schemata;
};

int libcrun_container_update_intel_rdt (libcrun_context_t *ctx, const char *id,
                                        struct libcrun_intel_rdt_update *update, libcrun_error_t *err);

/* Add or remove mounts described by an OCI mounts JSON file.  */
int libcrun_container_add_mounts_from_file (libcrun_context_t *ctx, const char *id, const char *file,
                                            libcrun_error_t *err);
int libcrun_container_remove_mounts_from_file (libcrun_context_t *ctx, const char *id, const char *file,
                                               libcrun_error_t *err);

/* Enumerate the PIDs in a container; caller frees *pids with free().  */
int libcrun_container_read_pids (libcrun_context_t *ctx, const char *id, bool recurse, pid_t **pids,
                                 libcrun_error_t *err);

/* Checkpoint and restore (CRIU).  */
enum libcrun_cr_cgroups_mode
{
  LIBCRUN_CR_CG_MODE_DEFAULT = 0, /* soft, matching runc */
  LIBCRUN_CR_CG_MODE_SOFT,
  LIBCRUN_CR_CG_MODE_IGNORE,
  LIBCRUN_CR_CG_MODE_FULL,
  LIBCRUN_CR_CG_MODE_STRICT,
};

enum libcrun_cr_network_lock_method
{
  LIBCRUN_CR_NETWORK_LOCK_DEFAULT = 0, /* iptables */
  LIBCRUN_CR_NETWORK_LOCK_IPTABLES,
  LIBCRUN_CR_NETWORK_LOCK_NFTABLES,
  LIBCRUN_CR_NETWORK_LOCK_SKIP,
};

struct libcrun_checkpoint_restore_options_s
{
  size_t struct_size; /* set to sizeof (struct libcrun_checkpoint_restore_options_s) */

  const char *image_path;
  const char *work_path;
  const char *parent_path;
  const char *console_socket;
  const char *lsm_profile;
  const char *lsm_mount_context;

  bool leave_running;
  bool tcp_established;
  bool tcp_close;
  bool ext_unix_sk;
  bool shell_job;
  bool file_locks;
  bool pre_dump;
  bool detach;

  int manage_cgroups_mode; /* enum libcrun_cr_cgroups_mode */
  int network_lock_method; /* enum libcrun_cr_network_lock_method */
};

int libcrun_container_checkpoint (libcrun_context_t *ctx, const char *id,
                                  struct libcrun_checkpoint_restore_options_s *opts, libcrun_error_t *err);
int libcrun_container_restore (libcrun_context_t *ctx, const char *id,
                               struct libcrun_checkpoint_restore_options_s *opts, libcrun_error_t *err);

/* Feature tags contributed by the loaded handlers, as a NULL-terminated array of
   strings (e.g. "wasm:wasmedge").  Returns NULL if there are none.  Caller frees the
   array and each string with free().  */
char **libcrun_context_get_handler_feature_tags (libcrun_context_t *ctx, libcrun_error_t *err);

#ifdef __cplusplus
}
#endif

#endif
