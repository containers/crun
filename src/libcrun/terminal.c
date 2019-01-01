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

#define _XOPEN_SOURCE

#define _GNU_SOURCE

#include <config.h>
#include "linux.h"
#include "utils.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>

struct terminal_status_s
{
  int fd;
  struct termios termios;
};


int
libcrun_new_terminal (char **slave, libcrun_error_t *err)
{
  char buf[64];
  int ret;
  cleanup_close int fd = open ("/dev/ptmx", O_RDWR, O_NOCTTY | O_CLOEXEC);
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

static int
set_raw (int fd, libcrun_error_t *err)
{
  int ret;
  struct termios termios;

  ret = tcgetattr (fd, &termios);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "tcgetattr");

  cfmakeraw (&termios);
  termios.c_oflag |= OPOST;

  ret = tcsetattr (fd, TCSANOW, &termios);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "tcsetattr");

  return 0;
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

int
libcrun_setup_terminal_master (int fd, void **current_status, libcrun_error_t *err)
{
  int ret;
  struct termios termios;

  ret = tcgetattr (fd, &termios);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "tcgetattr");

  if (current_status)
    {
      struct terminal_status_s *s = xmalloc (sizeof (*s));
      s->fd = 0;
      memcpy (&(s->termios), &termios, sizeof (termios));
      *current_status = s;
    }

  termios.c_oflag |= OPOST;

  ret = tcsetattr (fd, TCSANOW, &termios);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "tcsetattr");

  return set_raw (0, err);
}

void
cleanup_terminalp (void *p)
{
  struct terminal_status_s **s = (struct terminal_status_s **) p;
  if (*s)
    {
      tcsetattr ((*s)->fd, TCSANOW, &(*s)->termios);
      free (*s);
    }
}

int
libcrun_terminal_setup_size (int fd, unsigned short rows, unsigned short cols, libcrun_error_t *err)
{
  struct winsize ws = {.ws_row = rows, .ws_col = cols};
  int ret = ioctl (0, TIOCSWINSZ, &ws);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "ioctl TIOCSWINSZ");
  return 0;
}
