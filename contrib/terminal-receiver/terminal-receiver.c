/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#define _GNU_SOURCE

#include <config.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "error.h"
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>

int
open_unix_domain_socket (const char *path)
{
  struct sockaddr_un addr;
  int ret;
  int fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    error (EXIT_FAILURE, errno, "error creating UNIX socket");

  memset (&addr, 0, sizeof (addr));
  strcpy (addr.sun_path, path);
  addr.sun_family = AF_UNIX;
  ret = bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  if (ret < 0)
    error (EXIT_FAILURE, errno, "error binding UNIX socket");

  ret = listen (fd, 1);
  if (ret < 0)
    error (EXIT_FAILURE, errno, "listen");

  return fd;
}

int
receive_fd_from_socket (int from)
{
  int fd = -1;
  struct iovec iov[1];
  struct msghdr msg;
  char ctrl_buf[CMSG_SPACE (sizeof (int))];
  char data[1];
  int ret;
  struct cmsghdr *cmsg;
  memset (&msg, 0, sizeof (struct msghdr));
  memset (ctrl_buf, 0, CMSG_SPACE (sizeof (int)));

  data[0] = ' ';
  iov[0].iov_base = data;
  iov[0].iov_len = sizeof (data);

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_controllen = CMSG_SPACE (sizeof (int));
  msg.msg_control = ctrl_buf;

  ret = TEMP_FAILURE_RETRY (recvmsg (from, &msg, 0));
  if (ret < 0)
    {
      error (0, errno, "recvmsg");
      return -1;
    }

  cmsg = CMSG_FIRSTHDR (&msg);
  if (cmsg == NULL)
    {
      error (0, 0, "no msg received");
      return -1;
    }
  memcpy (&fd, CMSG_DATA (cmsg), sizeof (fd));

  return fd;
}

int
main (int argc, char **argv)
{
  char buf[8192];
  int ret, fd, socket;
  if (argc < 2)
    error (EXIT_FAILURE, 0, "usage %s PATH\n", argv[0]);

  unlink (argv[1]);

  socket = open_unix_domain_socket (argv[1]);
  while (1)
    {
      struct termios tset;
      int conn = TEMP_FAILURE_RETRY (accept (socket, NULL, NULL));
      if (conn < 0)
        error (EXIT_FAILURE, errno, "accept");

      fd = receive_fd_from_socket (conn);
      if (fd < 0)
        {
          close (conn);
          continue;
        }

      if (tcgetattr(fd, &tset) == -1)
        error (0, errno, "failed to get console terminal settings");

      tset.c_oflag |= ONLCR;

      if (tcsetattr (fd, TCSANOW, &tset) == -1)
        error (0, errno, "failed to set console terminal settings");

      while (1)
        {
          ret = read (fd, buf, sizeof (buf));
          if (ret == 0)
            break;
          if (ret < 0)
            {
              error (0, errno, "read");
              close (conn);
              break;
            }
          write (1, buf, ret);
        }
      close (conn);
    }

  return 0;
}
