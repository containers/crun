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
#ifndef UTILS_H
#define UTILS_H

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <argp.h>
#include "error.h"
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <ocispec/runtime_spec_schema_config_schema.h>
#include <sys/wait.h>
#include "container.h"

#ifndef TEMP_FAILURE_RETRY
#  define TEMP_FAILURE_RETRY(expression)      \
    (__extension__ ({                         \
      long int __result;                      \
      do                                      \
        __result = (long int) (expression);   \
      while (__result < 0 && errno == EINTR); \
      __result;                               \
    }))
#endif

#define cleanup_file __attribute__ ((cleanup (cleanup_filep)))
#define cleanup_free __attribute__ ((cleanup (cleanup_freep)))
#define cleanup_close __attribute__ ((cleanup (cleanup_closep)))
#define cleanup_close_vec __attribute__ ((cleanup (cleanup_close_vecp)))
#define cleanup_close_map __attribute__ ((cleanup (cleanup_close_mapp)))
#define cleanup_dir __attribute__ ((cleanup (cleanup_dirp)))
#define arg_unused __attribute__ ((unused))
#define cleanup_pid __attribute__ ((cleanup (cleanup_pidp)))
#define cleanup_mmap __attribute__ ((cleanup (cleanup_mmapp)))

#define LIKELY(x) __builtin_expect ((x), 1)
#define UNLIKELY(x) __builtin_expect ((x), 0)

__attribute__ ((malloc)) static inline void *
xmalloc (size_t size)
{
  void *res = malloc (size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

__attribute__ ((malloc)) static inline void *
xmalloc0 (size_t size)
{
  void *res = calloc (1, size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

__attribute__ ((malloc)) static inline void *
xrealloc (void *ptr, size_t size)
{
  void *res = realloc (ptr, size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

static inline void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

static inline void
cleanup_filep (FILE **f)
{
  FILE *file = *f;
  if (file)
    (void) fclose (file);
}

static inline void
cleanup_closep (void *p)
{
  int *pp = (int *) p;
  if (*pp >= 0)
    TEMP_FAILURE_RETRY (close (*pp));
}

static inline void
cleanup_pidp (void *p)
{
  pid_t *pp = (pid_t *) p;
  if (*pp > 0)
    {
      TEMP_FAILURE_RETRY (kill (*pp, SIGKILL));
      TEMP_FAILURE_RETRY (waitpid (*pp, NULL, 0));
    }
}

struct libcrun_mmap_s
{
  void *addr;
  size_t length;
};

int libcrun_mmap (struct libcrun_mmap_s **ret, void *addr, size_t length,
                  int prot, int flags, int fd, off_t offset,
                  libcrun_error_t *err);

int libcrun_munmap (struct libcrun_mmap_s *mmap, libcrun_error_t *err);

static inline void
cleanup_mmapp (void *p)
{
  int ret;
  libcrun_error_t tmp_err = NULL;
  struct libcrun_mmap_s **mm;

  mm = (struct libcrun_mmap_s **) p;
  if (*mm == NULL)
    return;

  ret = libcrun_munmap (*mm, &tmp_err);
  if (UNLIKELY (ret < 0))
    crun_error_release (&tmp_err);
}

struct libcrun_fd_map
{
  size_t nfds;
  int fds[];
};

static inline struct libcrun_fd_map *
make_libcrun_fd_map (size_t len)
{
  struct libcrun_fd_map *ret;
  size_t i;

  ret = (struct libcrun_fd_map *) xmalloc (sizeof (*ret) + sizeof (int) * len);
  ret->nfds = len;
  for (i = 0; i < len; i++)
    ret->fds[i] = -1;

  return ret;
}

static inline void
cleanup_close_mapp (struct libcrun_fd_map **p)
{
  struct libcrun_fd_map *m = *p;
  size_t i;

  if (m == NULL)
    return;

  for (i = 0; i < m->nfds; i++)
    if (m->fds[i] >= 0)
      TEMP_FAILURE_RETRY (close (m->fds[i]));

  free (m);
}

static inline void
cleanup_close_vecp (int **p)
{
  int *pp = *p;
  int i;

  for (i = 0; pp[i] >= 0; i++)
    TEMP_FAILURE_RETRY (close (pp[i]));
}

static inline void
cleanup_dirp (DIR **p)
{
  DIR *dir = *p;
  if (dir)
    closedir (dir);
}

static inline int
close_and_reset (int *fd)
{
  int ret = 0;
  if (*fd >= 0)
    {
      ret = TEMP_FAILURE_RETRY (close (*fd));
      if (LIKELY (ret == 0))
        *fd = -1;
    }
  return ret;
}

static inline char *
xstrdup (const char *str)
{
  char *ret;
  if (str == NULL)
    return NULL;

  ret = strdup (str);
  if (ret == NULL)
    OOM ();

  return ret;
}

static inline const char *
consume_slashes (const char *t)
{
  while (*t == '/')
    t++;
  return t;
}

static inline bool
path_is_slash_dev (const char *path)
{
  path = consume_slashes (path);

  if (strncmp (path, "dev", 3))
    return false;

  path += 3;

  /* Check there are only '/' left.  */
  for (; *path; path++)
    if (*path != '/')
      return false;

  return true;
}

int xasprintf (char **str, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));

int crun_path_exists (const char *path, libcrun_error_t *err);

int write_file_with_flags (const char *name, int flags, const void *data, size_t len, libcrun_error_t *err);

int write_file (const char *name, const void *data, size_t len, libcrun_error_t *err);

int write_file_at (int dirfd, const char *name, const void *data, size_t len, libcrun_error_t *err);

int write_file_at_with_flags (int dirfd, int flags, mode_t mode, const char *name, const void *data, size_t len, libcrun_error_t *err);

int crun_ensure_directory (const char *path, int mode, bool nofollow, libcrun_error_t *err);

int crun_ensure_file (const char *path, int mode, bool nofollow, libcrun_error_t *err);

int crun_ensure_directory_at (int dirfd, const char *path, int mode, bool nofollow, libcrun_error_t *err);

int crun_ensure_file_at (int dirfd, const char *path, int mode, bool nofollow, libcrun_error_t *err);

int crun_safe_create_and_open_ref_at (bool dir, int dirfd, const char *dirpath, size_t dirpath_len, const char *path, int mode, libcrun_error_t *err);

int crun_safe_ensure_directory_at (int dirfd, const char *dirpath, size_t dirpath_len, const char *path, int mode,
                                   libcrun_error_t *err);

int crun_safe_ensure_file_at (int dirfd, const char *dirpath, size_t dirpath_len, const char *path, int mode,
                              libcrun_error_t *err);

int crun_dir_p (const char *path, bool nofollow, libcrun_error_t *err);

int crun_dir_p_at (int dirfd, const char *path, bool nofollow, libcrun_error_t *err);

int detach_process ();

int create_file_if_missing_at (int dirfd, const char *file, libcrun_error_t *err);

int check_running_in_user_namespace (libcrun_error_t *err);

int set_selinux_label (const char *label, bool now, libcrun_error_t *err);

int add_selinux_mount_label (char **ret, const char *data, const char *label, const char *context_type, libcrun_error_t *err);

int set_apparmor_profile (const char *profile, bool now, libcrun_error_t *err);

int read_all_fd_with_size_hint (int fd, const char *description, char **out, size_t *len, size_t hint, libcrun_error_t *err);

static inline int
read_all_fd (int fd, const char *description, char **out, size_t *len, libcrun_error_t *err)
{
  return read_all_fd_with_size_hint (fd, description, out, len, 0, err);
}

int read_all_file (const char *path, char **out, size_t *len, libcrun_error_t *err);

int read_all_file_at (int dirfd, const char *path, char **out, size_t *len, libcrun_error_t *err);

int open_unix_domain_client_socket (const char *path, int dgram, libcrun_error_t *err);

int open_unix_domain_socket (const char *path, int dgram, libcrun_error_t *err);

int send_fd_to_socket (int server, int fd, libcrun_error_t *err);

int send_fd_to_socket_with_payload (int server, int fd, const char *payload, size_t payload_len, libcrun_error_t *err);

int create_socket_pair (int *pair, libcrun_error_t *err);

int receive_fd_from_socket (int from, libcrun_error_t *err);

int receive_fd_from_socket_with_payload (int from, char *payload, size_t payload_len, libcrun_error_t *err);

int create_signalfd (sigset_t *mask, libcrun_error_t *err);

int epoll_helper (int *fds, int *levelfds, libcrun_error_t *err);

int copy_from_fd_to_fd (int src, int dst, int consume, libcrun_error_t *err);

int run_process (char **args, libcrun_error_t *err);

size_t format_default_id_mapping (char **ret, uid_t container_id, uid_t host_uid, uid_t host_id, int is_uid);

int run_process_with_stdin_timeout_envp (char *path, char **args, const char *cwd, int timeout, char **envp,
                                         char *stdin, size_t stdin_len, int out_fd, int err_fd, libcrun_error_t *err);

int mark_or_close_fds_ge_than (int n, bool close_now, libcrun_error_t *err);

void get_current_timestamp (char *out, size_t len);

int set_blocking_fd (int fd, int blocking, libcrun_error_t *err);

int parse_json_file (yajl_val *out, const char *jsondata, struct parser_context *ctx, libcrun_error_t *err);

static inline int
has_prefix (const char *str, const char *prefix)
{
  size_t prefix_len = strlen (prefix);
  return strlen (str) >= prefix_len && memcmp (str, prefix, prefix_len) == 0;
}

char *find_executable (const char *executable_path, const char *cwd);

int copy_recursive_fd_to_fd (int srcfd, int destfd, const char *srcname, const char *destname, libcrun_error_t *err);

int set_home_env (uid_t uid);

int libcrun_initialize_selinux (libcrun_error_t *err);

int libcrun_initialize_apparmor (libcrun_error_t *err);

const char *find_annotation_map (json_map_string_string *annotations, const char *name);
const char *find_annotation (libcrun_container_t *container, const char *name);

int get_file_type_at (int dirfd, mode_t *mode, bool nofollow, const char *path);

int get_file_type (mode_t *mode, bool nofollow, const char *path);

int get_file_type_fd (int fd, mode_t *mode);

char *get_user_name (uid_t uid);

int safe_openat (int dirfd, const char *rootfs, size_t rootfs_len, const char *path, int flags, int mode,
                 libcrun_error_t *err);

ssize_t safe_write (int fd, const void *buf, ssize_t count);

int append_paths (char **out, libcrun_error_t *err, ...) __attribute__ ((sentinel));

int str2sig (const char *name);

int base64_decode (const char *iptr, size_t isize, char *optr, size_t osize, size_t *nbytes);
int has_suffix (const char *source, const char *suffix);
char *str_join_array (int offset, size_t size, char *const array[], const char *joint);

ssize_t safe_readlinkat (int dfd, const char *name, char **buffer, ssize_t hint, libcrun_error_t *err);

static inline bool
is_empty_string (const char *s)
{
  return s == NULL || s[0] == '\0';
}

static inline int
waitpid_ignore_stopped (pid_t pid, int *status, int options)
{
  int ret, s = 0;
  do
    {
      ret = TEMP_FAILURE_RETRY (waitpid (pid, &s, options));
      if (ret < 0)
        return ret;
  } while (WIFSTOPPED (s) | WIFCONTINUED (s));

  if (status)
    *status = s;

  return ret;
}

static inline int
get_process_exit_status (int status)
{
  if (WIFEXITED (status))
    return WEXITSTATUS (status);
  if (WIFSIGNALED (status))
    return 128 + WTERMSIG (status);

  return -1;
}

uid_t get_overflow_uid (void);
gid_t get_overflow_gid (void);

/* Adapted from systemd.  Include space for the NUL byte.  */
#define DECIMAL_STR_MAX(type)                                        \
  ((size_t) 2U + (sizeof (type) <= 1 ? 3U : sizeof (type) <= 2 ? 5U  \
                                        : sizeof (type) <= 4   ? 10U \
                                        : sizeof (type) <= 8   ? 20U \
                                                               : sizeof (int[-2 * (sizeof (type) > 8)])))

#define _STRLEN(s) (sizeof (s) - 1)

/* _STRLEN("self") < DECIMAL_STR_MAX (pid_t), so we don't need to calculate the length of both.  */
#define PROC_PID_FD_STRLEN (_STRLEN ("/proc/") + DECIMAL_STR_MAX (pid_t) \
                            + _STRLEN ("/fd/") + DECIMAL_STR_MAX (int))

/* A buffer long enough to hold either /proc/self/fd/$FD or a /proc/$PID/fd/$FD path.  */
typedef char proc_fd_path_t[PROC_PID_FD_STRLEN];

#undef _STRLEN

static inline void
get_proc_fd_path (proc_fd_path_t path, pid_t pid, int fd)
{
  const size_t max_len = sizeof (proc_fd_path_t);
  size_t n;

  if (pid)
    n = snprintf (path, max_len, "/proc/%d/fd/%d", pid, fd);
  else
    n = snprintf (path, max_len, "/proc/self/fd/%d", fd);

  if (UNLIKELY (n >= max_len))
    abort ();
}

static inline void
get_proc_self_fd_path (proc_fd_path_t path, int fd)
{
  get_proc_fd_path (path, 0, fd);
}

#endif
