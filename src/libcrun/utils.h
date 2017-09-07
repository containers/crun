/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
 * libocispec is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libocispec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef UTILS_H
# define UTILS_H
# include <config.h>
# include <stdio.h>
# include <stdlib.h>
# include <error.h>
# include <errno.h>
# include <argp.h>
# include "error.h"

void cleanup_freep (void *p);
void cleanup_closep (void *p);

#define cleanup_free __attribute__((cleanup (cleanup_freep)))
#define cleanup_close __attribute__((cleanup (cleanup_closep)))

# define LIKELY(x) __builtin_expect((x),1)
# define UNLIKELY(x) __builtin_expect((x),0)

void *xmalloc (size_t size);

void *xrealloc (void *ptr, size_t size);

char *xstrdup (const char *str);

int xasprintf (char **str, const char *fmt, ...);

char *argp_mandatory_argument (char *arg, struct argp_state *state);

int crun_path_exists (const char *path, int readonly, libcrun_error_t *err);

int write_file (const char *name, const void *data, size_t len, libcrun_error_t *err);

int write_file_at (int dirfd, const char *name, const void *data, size_t len, libcrun_error_t *err);

int crun_ensure_directory (const char *path, int mode, libcrun_error_t *err);

int detach_process ();

int create_file_if_missing_at (int dirfd, const char *file, libcrun_error_t *err);

int check_running_in_user_namespace (libcrun_error_t *err);

int set_selinux_exec_label (const char *label, libcrun_error_t *err);

int add_selinux_mount_label (char **ret, const char *data, const char *label, libcrun_error_t *err);

int read_all_file (const char *path, char **out, size_t *len, libcrun_error_t *err);

int open_unix_domain_socket (const char *path, libcrun_error_t *err);

int send_fd_to_socket (int server, int fd, libcrun_error_t *err);

int create_socket_pair (int *pair, libcrun_error_t *err);

int receive_fd_from_socket (int from, libcrun_error_t *err);

#endif
