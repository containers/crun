/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
 * libocispec is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libocispec is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <config.h>
#include "utils.h"
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

#ifdef HAVE_SELINUX
# include <selinux/selinux.h>
#endif

void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

void
cleanup_filep (FILE **f)
{
  FILE *file = *f;
  if (file)
    (void) fclose (file);
}

void
cleanup_closep (void *p)
{
  int *pp = p;
  if (*pp >= 0)
    close (*pp);
}

void
cleanup_dirp (DIR **p)
{
  DIR *dir = *p;
  if (dir)
    closedir (dir);
}

void *
xmalloc (size_t size)
{
  void *res = malloc (size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

void *
xrealloc (void *ptr, size_t size)
{
  void *res = realloc (ptr, size);
  if (UNLIKELY (res == NULL))
    OOM ();
  return res;
}

char *
argp_mandatory_argument (char *arg, struct argp_state *state)
{
  if (arg)
    return arg;
  return state->argv[state->next++];
}

int
crun_path_exists (const char *path, int readonly, libcrun_error_t *err)
{
  int ret = access (path, readonly ? R_OK : W_OK);
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "accessing file '%s'", path);
  return !ret;
}

int
xasprintf (char **str, const char *fmt, ...)
{
  int ret;
  va_list args_list;

  va_start (args_list, fmt);

  ret = vasprintf (str, fmt, args_list);
  if (UNLIKELY (ret < 0))
    OOM ();

  va_end (args_list);
  return ret;
}

char *
xstrdup (const char *str)
{
  char *ret;
  if (str == NULL)
    return NULL;

  ret = strdup (str);
  if (ret == NULL)
    OOM ();

  return ret;
}

int
write_file_at (int dirfd, const char *name, const void *data, size_t len, libcrun_error_t *err)
{
  cleanup_close int fd = openat (dirfd, name, O_WRONLY | O_CREAT, 0700);
  int ret;
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  if (len)
    {
      ret = write (fd, data, len);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "writing file '%s'", name);
    }

  return ret;
}

int
write_file (const char *name, const void *data, size_t len, libcrun_error_t *err)
{
  cleanup_close int fd = open (name, O_WRONLY | O_CREAT, 0700);
  int ret;
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  ret = write (fd, data, len);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "writing file '%s'", name);

  return ret;
}

int
detach_process ()
{
  pid_t pid;
  if (setsid () < 0)
    return -1;
  pid = fork ();
  if (pid < 0)
    return -1;
  if (pid != 0)
    _exit (EXIT_SUCCESS);
  return 0;
}

int
create_file_if_missing_at (int dirfd, const char *file, libcrun_error_t *err)
{
  int ret = faccessat (dirfd, file, R_OK, 0);
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "accessing file '%s'", file);

  if (ret)
    {
      cleanup_close int fd_write = openat (dirfd, file, O_CREAT | O_WRONLY, 0700);
      if (fd_write < 0)
        return crun_make_error (err, errno, "creating file '%s'", file);
    }
  return 0;
}

int
create_file_if_missing (const char *file, libcrun_error_t *err)
{
  int ret = access (file, R_OK);
  if (UNLIKELY (ret < 0 && errno != ENOENT))
    return crun_make_error (err, errno, "accessing file '%s'", file);

  if (ret)
    {
      cleanup_close int fd_write = open (file, O_CREAT | O_WRONLY, 0700);
      if (fd_write < 0)
        return crun_make_error (err, errno, "creating file '%s'", file);
    }
  return 0;
}

static int
ensure_directory_internal (char *path, size_t len, int mode, libcrun_error_t *err)
{
  char *it = path + len;
  int ret;
  ret = crun_path_exists (path, 1, err);
  if (ret > 0)
    return 0;

  while (it > path && *it != '/')
    {
      it--;
      len--;
    }
  if (it == path)
    return 0;

  *it = '\0';

  ret = ensure_directory_internal (path, len - 1, mode, err);
  if (UNLIKELY (ret < 0))
    return ret;
  *it = '/';

  ret = mkdir (path, mode);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "creating file '%s'", path);
  return 0;
}

int
crun_ensure_directory (const char *path, int mode, libcrun_error_t *err)
{
  cleanup_free char *tmp = xstrdup (path);
  return ensure_directory_internal (tmp, strlen (tmp), mode, err);
}

int
crun_ensure_file (const char *path, int mode, libcrun_error_t *err)
{
  cleanup_free char *tmp = xstrdup (path);
  size_t len = strlen (tmp);
  char *it = tmp + len - 1;
  int ret;
  
  while (*it != '/' && it > tmp)
    it--;
  if (it > tmp)
    {
      *it = '\0';
      ret = crun_ensure_directory (tmp, mode, err);
      if (UNLIKELY (ret < 0))
        return ret;
      *it = '/';

      return create_file_if_missing (tmp, err);
    }
  return 0;
}

int
check_running_in_user_namespace (libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  size_t len;
  int ret = read_all_file ("/proc/self/uid_map", &buffer, &len, err);
  if (UNLIKELY (ret < 0))
    return ret;
  return strstr (buffer, "4294967295") ? 1 : 0;
}

int
add_selinux_mount_label (char **ret, const char *data, const char *label, libcrun_error_t *err)
{
#ifdef HAVE_SELINUX
  if (label && is_selinux_enabled () > 0)
    {
      if (data && *data)
        xasprintf (ret, "%s,context=\"%s\"", data, label);
      else
        xasprintf (ret, "context=\"%s\"", label);
      return 0;
    }
#endif
  *ret = xstrdup (data);
  return 0;

}

int
set_selinux_exec_label (const char *label, libcrun_error_t *err)
{
#ifdef HAVE_SELINUX
  if (is_selinux_enabled () > 0)
    if (UNLIKELY (setexeccon (label) < 0))
      {
        crun_make_error (err, errno, "error setting SELinux exec label");
        return -1;
      }
#endif
  return 0;
}

int
read_all_file (const char *path, char **out, size_t *len, libcrun_error_t *err)
{
  cleanup_close int fd;
  int ret;
  cleanup_free char *buf = NULL;
  struct stat stat;
  size_t nread, allocated;

  fd = TEMP_FAILURE_RETRY (open (path, O_RDONLY));

  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "error opening file '%s'", path);

  ret = fstat (fd, &stat);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error stat'ing file '%s'", path);

  /* NUL terminate the buffer.  */
  allocated = stat.st_size;
  if (stat.st_size)
    allocated = 256;
  buf = xmalloc (allocated + 1);
  buf[stat.st_size] = '\0';
  nread = 0;
  while ((stat.st_size && nread < stat.st_size) || 1)
    {
      ret = TEMP_FAILURE_RETRY (read (fd, buf + nread, allocated - nread));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "error reading from file '%s'", path);

      nread += ret;

      if (nread < allocated)
        break;

      allocated += 256;
      buf = xrealloc (buf, allocated + 1);
      buf[allocated] = '\0';
    }
  *out = buf;
  buf = NULL;
  if (len)
    *len = nread;
  return 0;
}

int
open_unix_domain_socket (const char *path, int dgram, libcrun_error_t *err)
{
  struct sockaddr_un addr;
  int ret;
  cleanup_close int fd = socket (AF_UNIX, dgram ? SOCK_DGRAM : SOCK_STREAM, 0);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "error creating UNIX socket");

  memset (&addr, 0, sizeof (addr));
  strcpy (addr.sun_path, path);
  addr.sun_family = AF_UNIX;
  ret = bind (fd, (struct sockaddr *) &addr, sizeof (addr));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "bind socket to '%s'", path);

  if (!dgram)
    {
      ret = listen (fd, 1);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "listen on socket");
    }

  ret = fd;
  fd = -1;

  return ret;
}

int
send_fd_to_socket (int server, int fd, libcrun_error_t *err)
{
  int ret;
  struct cmsghdr *cmsg = NULL;
  struct iovec iov[1];
  struct msghdr msg;
  char ctrl_buf[CMSG_SPACE (sizeof (int))];
  char data[1];

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

  cmsg = CMSG_FIRSTHDR (&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN (sizeof (int));

  *((int *) CMSG_DATA (cmsg)) = fd;

  ret = TEMP_FAILURE_RETRY (sendmsg (server, &msg, 0));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sendmsg");
  return 0;
}

int
receive_fd_from_socket (int from, libcrun_error_t *err)
{
  cleanup_close int fd = -1;
  int ret;
  struct iovec iov[1];
  struct msghdr msg;
  char ctrl_buf[CMSG_SPACE (sizeof (int))];
  char data[1];
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
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "recvmsg");

  cmsg = CMSG_FIRSTHDR (&msg);
  if (cmsg == NULL)
    return crun_make_error (err, 0, "no msg received");
  memcpy (&fd, CMSG_DATA (cmsg), sizeof (fd));

  ret = fd;
  fd = -1;
  return ret;
}

int
create_socket_pair (int *pair, libcrun_error_t *err)
{
  int ret = socketpair (AF_UNIX, SOCK_DGRAM, 0, pair);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "socketpair");
  return 0;
}

int
create_signalfd (sigset_t *mask, libcrun_error_t *err)
{
  int ret = signalfd (-1, mask, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "signalfd");
  return ret;
}

int
epoll_helper (int *fds, libcrun_error_t *err)
{
  struct epoll_event ev;
  cleanup_close int epollfd = -1;
  int ret;

  int *it;
  epollfd = epoll_create1 (0);
  if (UNLIKELY (epollfd < 0))
    return crun_make_error (err, errno, "epoll_create1");

  for (it = fds; *it >= 0; it++)
    {
      ev.events = EPOLLIN;
      ev.data.fd = *it;
      ret = epoll_ctl (epollfd, EPOLL_CTL_ADD, *it, &ev);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "epoll_ctl add '%d'", *it);
    }

  ret = epollfd;
  epollfd = -1;
  return ret;
}

int
copy_from_fd_to_fd (int src, int dst, libcrun_error_t *err)
{
#ifdef HAVE_COPY_FILE_RANGE
  ret = copy_file_range (0, NULL, terminal_fd, NULL, 4096, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "copy_file_range");
  return 0;
#else
  cleanup_free char *buffer = xmalloc (8192);
  int ret, nread;
  nread = TEMP_FAILURE_RETRY (read (src, buffer, sizeof (buffer)));
  if (errno == EIO)
    return 0;
  if (UNLIKELY (nread < 0))
    return crun_make_error (err, errno, "read");

  while (nread)
    {
      ret = TEMP_FAILURE_RETRY (write (dst, buffer, nread));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "write");
      nread -= ret;
    }

  return 0;
#endif
}

int
run_process (char **args, libcrun_error_t *err)
{
  pid_t pid = fork ();
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "fork");
  if (pid)
    {
      int r, status;
      r = TEMP_FAILURE_RETRY (waitpid (pid, &status, 0));
      if (r < 0)
        return crun_make_error (err, errno, "waitpid");
      if (WIFEXITED (status) || WIFSIGNALED (status))
        return WEXITSTATUS (status);
    }

  execvp (args[0], args);
  _exit (EXIT_FAILURE);
}

/*if subuid or subgid exist, take the first range for the user */
static int
getsubidrange (uid_t id, int is_uid, uint32_t *from, uint32_t *len)
{
  cleanup_file FILE *input = NULL;
  cleanup_free char *lineptr = NULL;
  size_t lenlineptr = 0, len_name;
  const char *name;

  if (is_uid)
    {
      struct passwd *pwd = getpwuid (id);
      if (pwd == NULL)
        return -1;
      name = pwd->pw_name;
    }
  else
    {
      struct group *grp = getgrgid (id);
      if (grp == NULL)
        return -1;
      name = grp->gr_name;
    }

  len_name = strlen (name);

  input = fopen (is_uid ? "/etc/subuid" : "/etc/subgid", "r");
  if (input == NULL)
    return -1;

  for (;;)
    {
      char *endptr;
      int read = getline (&lineptr, &lenlineptr, input);
      if (read < 0)
        return -1;

      if (read < len_name + 2)
        continue;

      if (memcmp (lineptr, name, len_name) || lineptr[len_name] != ':')
        continue;

      *from = strtoull (&lineptr[len_name + 1], &endptr, 10);

      if (endptr >= &lineptr[read])
        return -1;

      *len = strtoull (&endptr[1], &endptr, 10);

      return 0;
    }
}

#define MIN(x,y) ((x)<(y)?(x):(y))

size_t
format_default_id_mapping (char **ret, uid_t container_id, uid_t host_id, int is_uid)
{
  uint32_t from, available;
  cleanup_free char *buffer = NULL;
  size_t written = 0;

  *ret = NULL;

  if (getsubidrange (host_id, is_uid, &from, &available) < 0)
    return 0;

  /* More than enough space for all the mappings.  */
  buffer = xmalloc (15 * 5 * 3);

  if (container_id > 0)
    {
      uint32_t used = MIN (container_id, available);
      written += sprintf (buffer + written, "%d %d %d\n", 0, from, used);
      from += used;
      available -= used;
    }

  /* Host ID -> Container ID.  */
  written += sprintf (buffer + written, "%d %d 1\n", container_id, host_id);

  /* Last mapping: use any id that is left.  */
  if (available)
    written += sprintf (buffer + written, "%d %d %d\n", container_id + 1, from, available);

  *ret = buffer;
  buffer = NULL;
  return written;
}

/* will leave SIGCHLD blocked if TIMEOUT is used.  */
int
run_process_with_stdin_timeout_envp (char *path,
                                     char **args,
                                     int timeout,
                                     char **envp,
                                     char *stdin,
                                     size_t stdin_len,
                                     libcrun_error_t *err)
{
  int stdin_pipe[2];
  pid_t pid;
  int ret;
  cleanup_close int pipe_r = -1;
  cleanup_close int pipe_w = -1;
  sigset_t mask;

  ret = pipe (stdin_pipe);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipe_r = stdin_pipe[0];
  pipe_w = stdin_pipe[1];

  if (timeout > 0)
    {
      sigaddset (&mask, SIGCHLD);
      ret = sigprocmask (SIG_BLOCK, &mask, NULL);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "sigprocmask");
    }

  pid = fork ();
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "fork");

  if (pid)
    {
      int r, status;

      close (pipe_r);
      pipe_r = -1;

      ret = write (pipe_w, stdin, stdin_len);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "writing to pipe");

      if (timeout)
        {
          time_t start = time (NULL);
          time_t now;
          for (now = start; now - start < timeout; now = time (NULL))
            {
              siginfo_t info;
              int elapsed = now - start;
              struct timespec ts_timeout = { .tv_sec = timeout - elapsed, .tv_nsec = 0 };

              ret = sigtimedwait (&mask, &info, &ts_timeout);
              if (UNLIKELY (ret < 0 && errno != EAGAIN))
                return crun_make_error (err, errno, "sigtimedwait");

              if (info.si_signo == SIGCHLD && info.si_pid == pid)
                goto read_waitpid;

              if (ret < 0 && errno == EAGAIN)
                goto timeout;
            }
 timeout:
          kill (pid, SIGKILL);
          return crun_make_error (err, 0, "timeout expired for '%s'", path);
        }

 read_waitpid:
      r = TEMP_FAILURE_RETRY (waitpid (pid, &status, 0));
      if (r < 0)
        return crun_make_error (err, errno, "waitpid");
      if (WIFEXITED (status) || WIFSIGNALED (status))
        return WEXITSTATUS (status);
    }

  close (pipe_w);
  dup2 (pipe_r, 0);
  close (pipe_r);
  execvpe (path, args, envp);
  _exit (1);
}

int
close_fds_ge_than (int n, libcrun_error_t *err)
{
  int fd;
  cleanup_dir DIR *dir = NULL;
  int ret;
  struct dirent *next;

  dir = opendir ("/proc/self/fd");
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, errno, "cannot fdopendir /proc/self/fd");

  fd = dirfd (dir);

  for (next = readdir (dir); next; next = readdir (dir))
    {
      int val;
      const char *name = next->d_name;
      if (name[0] == '.')
        continue;

      val = strtoll (name, NULL, 10);
      if (val < n || val == fd)
        continue;
      ret = close (val);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "cannot close fd for '/proc/self/fd/%s'", name);
    }
  return 0;
}
