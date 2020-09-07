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
#ifndef KONTAIN_H
#define KONTAIN_H

#include "crun.h"

#define APP_KONTAIN_USEVIRT "app.kontain.use-virt"
int add_kontain_config (libcrun_container_t *container);

#endif
