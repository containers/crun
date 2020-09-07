/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020 Kontain Inc.
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
#ifndef DEBUG_H
#define DEBUG_H

#include "crun.h"

void dumpmounts(libcrun_container_t *container);
void dumpdevices(libcrun_container_t *container);
void dumpannotations(libcrun_container_t *container);
void dumpconfig(const char *config_file);
void runtime_spec_to_file(runtime_spec_schema_config_schema *container);
void dump_crun_context(libcrun_context_t *context);
void debug(char *fmt, ...);

#endif
