/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019, 2024 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
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

#define _GNU_SOURCE

#include <libcrun/ring_buffer.h>
#include <libcrun/utils.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

typedef int (*test) ();

static void
fill_data (char *buffer, size_t size)
{
  size_t i;
  buffer[0] = rand () % 256;
  for (i = 1; i < size; i++)
    buffer[i] = buffer[i - 1] + 13;
}

static int
do_test_ring_buffer_read_write (int max_data_size, int rb_size)
{
  const int repeat = 2048;
  cleanup_free char *buffer_w = xmalloc (max_data_size);
  cleanup_free char *buffer_r = xmalloc (max_data_size);
  libcrun_error_t err = NULL;
  int fds_to_close[5] = {
    -1,
  };
  int fds_to_close_n = 0;
  cleanup_close_vec int *autocleanup_fds = fds_to_close;
  cleanup_ring_buffer struct ring_buffer *rb = NULL;
  int ret = 0;
  int fd_w[2];
  int fd_r[2];
  size_t i;

  if (max_data_size > rb_size)
    {
      fprintf (stderr, "max_data_size must be smaller than rb_size\n");
      return 1;
    }
  if (pipe2 (fd_w, O_NONBLOCK) < 0)
    {
      fprintf (stderr, "failed to create pipe\n");
      return 1;
    }
  if (pipe2 (fd_r, O_NONBLOCK) < 0)
    {
      fprintf (stderr, "failed to create pipe\n");
      return 1;
    }

  /* use a bigger buffer size for the pipe to be sure synchronization
   * between reads and writes is not just a side effect of the
   * underlying buffer size.  */
  ret = fcntl (fd_w[0], F_SETPIPE_SZ, max_data_size * 2);
  if (ret < 0)
    {
      fprintf (stderr, "failed to set pipe size\n");
      return 1;
    }
  ret = fcntl (fd_r[0], F_SETPIPE_SZ, max_data_size * 2);
  if (ret < 0)
    {
      fprintf (stderr, "failed to set pipe size\n");
      return 1;
    }

  fds_to_close[fds_to_close_n++] = fd_w[0];
  fds_to_close[fds_to_close_n++] = fd_w[1];
  fds_to_close[fds_to_close_n++] = fd_r[0];
  fds_to_close[fds_to_close_n++] = fd_r[1];
  fds_to_close[fds_to_close_n++] = -1;

  rb = ring_buffer_make (rb_size);

  fill_data (buffer_w, max_data_size);

  for (i = 0; i < repeat; i++)
    {
      bool is_eagain = false;
      size_t avail;
      size_t data_size = 1 + (i % max_data_size);

      memset (buffer_r, 0, max_data_size);

      fill_data (buffer_w, data_size);
      avail = ring_buffer_get_size (rb);
      if (avail != rb_size)
        {
          fprintf (stderr, "wrong get_size\n");
          return 1;
        }

      avail = ring_buffer_get_data_available (rb);
      if (avail != 0)
        {
          fprintf (stderr, "wrong get_data_available for empty ring buffer\n");
          return 1;
        }

      ret = write (fd_r[1], buffer_w, data_size);
      if (ret != data_size)
        {
          fprintf (stderr, "write failed\n");
          return 1;
        }

      ret = ring_buffer_read (rb, fd_r[0], &is_eagain, &err);
      if (ret < 0)
        {
          libcrun_error_release (&err);
          fprintf (stderr, "read from ring_buffer failed\n");
          return 1;
        }
      if (is_eagain)
        {
          fprintf (stderr, "read from ring_buffer failed with EAGAIN\n");
          return 1;
        }
      avail = ring_buffer_get_data_available (rb);
      if (avail != ret)
        {
          fprintf (stderr, "wrong get_data_available got %zu instead of %zu\n", avail, ret);
          return 1;
        }
      avail = ring_buffer_get_space_available (rb);
      if (avail != rb_size - ret)
        {
          fprintf (stderr, "wrong get_space_available got %zu instead of %zu\n", avail, rb_size - ret);
          return 1;
        }

      ret = ring_buffer_write (rb, fd_w[1], &is_eagain, &err);
      if (ret < 0)
        {
          libcrun_error_release (&err);
          fprintf (stderr, "write to ring_buffer failed\n");
          return 1;
        }
      if (is_eagain)
        {
          fprintf (stderr, "write failed with EAGAIN\n");
          return 1;
        }
      if (ret != data_size)
        {
          fprintf (stderr, "write to ring_buffer wrong size\n");
          return 1;
        }
      avail = ring_buffer_get_data_available (rb);
      if (avail != 0)
        {
          fprintf (stderr, "wrong get_data_available got %zu instead of 0\n", avail);
          return 1;
        }
      avail = ring_buffer_get_space_available (rb);
      if (avail != rb_size)
        {
          fprintf (stderr, "wrong get_space_available got %zu instead of %zu\n", avail, rb_size);
          return 1;
        }

      ret = read (fd_w[0], buffer_r, data_size);
      if (ret != data_size)
        {
          fprintf (stderr, "read wrong size\n");
          return 1;
        }
      if (memcmp (buffer_w, buffer_r, data_size) != 0)
        {
          fprintf (stderr, "data mismatch\n");
          return 1;
        }

      /* Try again with an empty fd and an empty ring buffer.  */
      is_eagain = false;
      ret = ring_buffer_read (rb, fd_r[0], &is_eagain, &err);
      if (ret < 0)
        {
          libcrun_error_release (&err);
          fprintf (stderr, "read to ring_buffer failed\n");
          return 1;
        }
      if (! is_eagain)
        {
          fprintf (stderr, "read should have returned EAGAIN\n");
          return 1;
        }

      is_eagain = false;
      ret = ring_buffer_write (rb, fd_w[1], &is_eagain, &err);
      if (ret < 0)
        {
          libcrun_error_release (&err);
          fprintf (stderr, "write to ring_buffer failed\n");
          return 1;
        }
      if (! is_eagain)
        {
          fprintf (stderr, "write should have returned EAGAIN\n");
          return 1;
        }
    }

  return 0;
}

static int
test_ring_buffer_read_write ()
{
  int max_data_sizes[] = { 1, 7, 10, 101, 1024, 4096, 4096, 7919, 8191, 8192 };
  int rb_sizes[] = { 11, 16, 128, 512, 2048, 4096, 4096, 8192, 8192, 8192 };
  int ret;
  int i;

  if (sizeof (max_data_sizes) != sizeof (rb_sizes))
    {
      fprintf (stderr, "internal error: max_data_sizes and rb_sizes must have the same length\n");
      return 1;
    }

  for (i = 0; i < sizeof (max_data_sizes) / sizeof (max_data_sizes[0]); i++)
    {
      ret = do_test_ring_buffer_read_write (max_data_sizes[i], rb_sizes[i]);
      if (ret < 0)
        {
          fprintf (stderr, "test failed with data_size=%d, rb_size=%d\n", max_data_sizes[i], rb_sizes[i]);
          return ret;
        }
    }
  return 0;
}

static void
run_and_print_test_result (const char *name, int id, test t)
{
  int ret = t ();
  if (ret == 0)
    printf ("ok %d - %s\n", id, name);
  else if (ret == 77)
    printf ("ok %d - %s #SKIP\n", id, name);
  else
    printf ("not ok %d - %s\n", id, name);
}

#define RUN_TEST(T)                            \
  do                                           \
    {                                          \
      run_and_print_test_result (#T, id++, T); \
  } while (0)

int
main ()
{
  int id = 1;
  printf ("1..1\n");

  RUN_TEST (test_ring_buffer_read_write);
  return 0;
}
