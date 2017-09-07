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

#define _XOPEN_SOURCE

#define _GNU_SOURCE

#include <config.h>
#include "linux.h"
#include "utils.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

int
libcrun_new_terminal (char **slave, libcrun_error_t *err)
{
  char buf[64];
  int ret;
  cleanup_close int fd = open ("/dev/ptmx", O_RDWR, O_NOCTTY | O_CLOEXEC, 0);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open /dev/ptmx");

  ret = ptsname_r (fd, buf, sizeof (buf));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "ptsname");

  ret = unlockpt (fd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "unlockpt");

  *slave = xstrdup (buf);

  ret = fd;
  fd = -1;

  return ret;
}

int
libcrun_set_stdio (char *slave, libcrun_error_t *err)
{
  int ret, i;
  cleanup_close int fd = open (slave, O_RDWR);

  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "open %s", slave);

  for (i = 0; i < 3; i++)
    {
      ret = dup3 (fd, i, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "dup terminal");
    }

  ret = ioctl (0, TIOCSCTTY, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "ioctl TIOCSCTTY");
  return 0;
}
