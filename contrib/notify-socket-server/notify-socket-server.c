/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2020 Giuseppe Scrivano <giuseppe@scrivano.org>
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

#define _GNU_SOURCE

#include <config.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <stdio.h>

#define error(status, errno, fmt, ...)                                      \
  do                                                                        \
    {                                                                       \
      if (errno)                                                            \
        fprintf (stderr, "crun: " fmt, ##__VA_ARGS__);                      \
      else                                                                  \
        fprintf (stderr, "crun: %s:" fmt, strerror (errno), ##__VA_ARGS__); \
      if (status)                                                           \
        exit (status);                                                      \
  } while (0)

static int
open_unix_domain_socket (const char *path)
{
  struct sockaddr_un addr = {};
  int ret, fd;
  const int one = 1;

  fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    error (EXIT_FAILURE, errno, "socket");

  if (strlen (path) >= sizeof (addr.sun_path))
    error (EXIT_FAILURE, 0, "invalid path");
  strcpy (addr.sun_path, path);
  addr.sun_family = AF_UNIX;
  ret = bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  if (ret < 0)
    error (EXIT_FAILURE, errno, "bind");

  ret = setsockopt (fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof (one));
  if (ret < 0)
    error (EXIT_FAILURE, errno, "setsockopt");

  return fd;
}

int
main (int argc, char **argv)
{
#define CTRL_SIZE (CMSG_SPACE (sizeof (struct ucred)))
  char buf[512];
  int ret, fd;
  if (argc < 2)
    error (EXIT_FAILURE, 0, "usage %s PATH\n", argv[0]);

  unlink (argv[1]);

  fd = open_unix_domain_socket (argv[1]);

  while (1)
    {
      char ctrl_buf[CTRL_SIZE] = {};
      struct cmsghdr *cmsg;
      char data[1];
      struct iovec iov[1];
      struct msghdr msg = {};
      struct ucred *ucred = NULL;

      iov[0].iov_base = buf;
      iov[0].iov_len = sizeof (buf) - 1;

      msg.msg_name = NULL;
      msg.msg_namelen = 0;
      msg.msg_iov = iov;
      msg.msg_iovlen = 1;
      msg.msg_control = ctrl_buf;
      msg.msg_controllen = CTRL_SIZE;

      ret = recvmsg (fd, &msg, MSG_CMSG_CLOEXEC | MSG_TRUNC);
      if (ret < 0 && errno == EINTR)
        continue;
      if (ret < 0)
        error (EXIT_FAILURE, errno, "recvfrom");

      buf[ret] = '\0';

      for (cmsg = CMSG_FIRSTHDR (&msg); cmsg; cmsg = CMSG_NXTHDR (&msg, cmsg))
        {
          if (cmsg
              && cmsg->cmsg_level == SOL_SOCKET
              && cmsg->cmsg_type == SCM_CREDENTIALS
              && cmsg->cmsg_len == CMSG_LEN (sizeof (struct ucred)))
            {
              ucred = (struct ucred *) CMSG_DATA (cmsg);
              break;
            }
        }

      if (ucred)
        printf ("RECEIVED (PID:%d UID:%d GID:%d): %s\n", ucred->pid, ucred->uid, ucred->gid, buf);
      else
        printf ("RECEIVED: %s\n", buf);
    }

  return 0;
}
