/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
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

#include <stdarg.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#include <stdio.h>

#define error(status, errno, fmt, ...)                                      \
  do                                                                        \
    {                                                                       \
      if (! errno)                                                          \
        fprintf (stderr, "crun: " fmt, ##__VA_ARGS__);                      \
      else                                                                  \
        fprintf (stderr, "crun: %s:" fmt, strerror (errno), ##__VA_ARGS__); \
      if (status)                                                           \
        exit (status);                                                      \
  } while (0)

struct termios tset;
int fd;

int
open_unix_domain_socket (const char *path)
{
  struct sockaddr_un addr = {};
  int ret;
  int fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    error (EXIT_FAILURE, errno, "error creating UNIX socket");
  if (strlen (path) >= sizeof (addr.sun_path))
    error (EXIT_FAILURE, 0, "invalid path");

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
  struct msghdr msg = {};
  char ctrl_buf[CMSG_SPACE (sizeof (int))] = {};
  char data[1];
  int ret;
  struct cmsghdr *cmsg;

  data[0] = ' ';
  iov[0].iov_base = data;
  iov[0].iov_len = sizeof (data);

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_controllen = CMSG_SPACE (sizeof (int));
  msg.msg_control = ctrl_buf;

  do
    ret = recvmsg (from, &msg, 0);
  while (ret < 0 && errno == EINTR);
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

void
sigint_handler (int s)
{
  const char ctrlc = 3;
  write (fd, &ctrlc, 1);
}

void
register_handler (struct sigaction *handler)
{
  handler->sa_handler = sigint_handler;
  sigemptyset (&handler->sa_mask);
  handler->sa_flags = 0;
  sigaction (SIGINT, handler, NULL);
}

int
main (int argc, char **argv)
{
  char buf[8192];
  int ret, socket;
  struct sigaction ctrl_c_handler;
  if (argc < 2)
    error (EXIT_FAILURE, 0, "usage %s PATH\n", argv[0]);

  unlink (argv[1]);

  register_handler (&ctrl_c_handler);

  socket = open_unix_domain_socket (argv[1]);
  while (1)
    {
      int conn;
      int stdin_flags, term_flags;
      int data;

      printf ("Press 'Ctrl \\' to exit.\nWaiting for connection ...\n");
      do
        conn = accept (socket, NULL, NULL);
      while (conn < 0 && errno == EINTR);
      if (conn < 0)
        error (EXIT_FAILURE, errno, "accept");

      fd = receive_fd_from_socket (conn);
      if (fd < 0)
        {
          close (conn);
          continue;
        }

      if (tcgetattr (fd, &tset) == -1)
        error (0, errno, "failed to get console terminal settings");

      tset.c_oflag |= ONLCR;
      tset.c_lflag &= ~ECHO;

      if (tcsetattr (fd, TCSANOW, &tset) == -1)
        error (0, errno, "failed to set console terminal settings");

      stdin_flags = fcntl (STDIN_FILENO, F_GETFL);
      if (stdin_flags == -1)
        error (EXIT_FAILURE, errno, "failed to obtain STDIN flags");

      ret = fcntl (STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);
      if (ret == -1)
        error (EXIT_FAILURE, errno, "failed to set STDIN to non-blocking");

      term_flags = fcntl (fd, F_GETFL);
      if (term_flags == -1)
        error (EXIT_FAILURE, errno, "failed to obtain terminal flags");

      ret = fcntl (fd, F_SETFL, term_flags | O_NONBLOCK);
      if (ret == -1)
        error (EXIT_FAILURE, errno, "failed to set terminal to non-blocking");

      while (1)
        {
          data = 0;
          ret = read (fd, buf, sizeof (buf));
          if (ret == 0)
            break;
          if (ret < 0 && errno != EAGAIN && errno != EINTR)
            {
              error (0, errno, "read\n");
              break;
            }
          if (ret > 0)
            {
              write (STDOUT_FILENO, buf, ret);
              data = 1;
            }

          ret = read (STDIN_FILENO, buf, sizeof (buf));
          if (ret > 0)
            {
              ret = write (fd, buf, ret);
              if (ret < 0 && errno != EAGAIN && errno != EINTR)
                {
                  error (0, errno, "write\n");
                  break;
                }
              data = 1;
            }
          if (! data)
            usleep (10000);
        }
      close (conn);
      ret = fcntl (STDIN_FILENO, F_SETFL, stdin_flags);
      if (ret == -1)
        error (EXIT_FAILURE, errno, "failed to reset STDIN to original setting");
      ret = fcntl (fd, F_SETFL, term_flags);
      if (ret == -1)
        error (EXIT_FAILURE, errno, "failed to reset terminal to original setting");
    }

  return 0;
}
