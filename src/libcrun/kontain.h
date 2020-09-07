/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020-2021 Kontain Inc.
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef KONTAIN_H
#define KONTAIN_H

#define KM_BIN_PATH "/opt/kontain/bin/km"
#define DOCKER_INIT_PATH "/sbin/docker-init"
#define PODMAN_INIT_PATH "/dev/init"
int libcrun_kontain_argv (char ***argv, const char **execpath);
int libcrun_kontain_nonkmexec_allowed (const char *execpath, char **execpath_allowed);
void libcrun_kontain_nonkmexec_clean (void);

#endif
