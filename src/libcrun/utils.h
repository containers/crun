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

void cleanup_freep (void *p);
void cleanup_closep (void *p);

#define cleanup_free __attribute__((cleanup (cleanup_freep)))
#define cleanup_close __attribute__((cleanup (cleanup_closep)))

# define LIKELY(x) __builtin_expect((x),1)
# define UNLIKELY(x) __builtin_expect((x),0)

# define OOM() do {error (EXIT_FAILURE, 0, "OOM");} while (0)

void *xmalloc (size_t size);

char *xstrdup (const char *str);

int xasprintf (char **str, const char *fmt, ...);

char *argp_mandatory_argument (char *arg, struct argp_state *state);

int crun_static_error (char **err, int status, const char *msg, ...);

int crun_path_exists (const char *path, int readonly, char **err);

int write_file (const char *name, const void *data, size_t len, char **err);

int crun_ensure_directory (const char *path, int mode, char **err);

int detach_process ();

int create_file_if_missing_at (int dirfd, const char *file, char **err);

int check_running_in_user_namespace (char **err);

int set_selinux_exec_label (const char *label, char **err);

int add_selinux_mount_label (char **ret, const char *data, const char *label, char **err);

#endif
