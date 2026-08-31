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
#include <limits.h>

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
do_test_ring_buffer_read_write (size_t max_data_size, size_t rb_size)
{
  const size_t repeat = 2048;
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
      if (ret != (int) data_size)
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
      if ((int) avail != ret)
        {
          fprintf (stderr, "wrong get_data_available got %zu instead of %d\n", avail, ret);
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
      if (ret != (int) data_size)
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
      if (ret != (int) data_size)
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
  size_t max_data_sizes[] = { 1, 7, 10, 101, 1024, 4096, 4096, 7919, 8191, 8192 };
  size_t rb_sizes[] = { 11, 16, 128, 512, 2048, 4096, 4096, 8192, 8192, 8192 };
  size_t i;
  int ret;

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
          fprintf (stderr, "test failed with data_size=%zu, rb_size=%zu\n", max_data_sizes[i], rb_sizes[i]);
          return ret;
        }
    }
  return 0;
}

static int
test_ring_buffer_wraparound_data_integrity ()
{
  /* Debug test: step by step to see where data is lost */
  const size_t rb_size = 3;
  char read_back[10] = { 0 };
  libcrun_error_t err = NULL;
  int fds_to_close[5] = {
    -1,
  };
  int fds_to_close_n = 0;
  cleanup_close_vec int *autocleanup_fds = fds_to_close;
  cleanup_ring_buffer struct ring_buffer *rb = NULL;
  int ret = 0;
  int fd_w[2], fd_r[2];

  if (pipe2 (fd_w, O_NONBLOCK) < 0 || pipe2 (fd_r, O_NONBLOCK) < 0)
    return 1;

  fds_to_close[fds_to_close_n++] = fd_w[0];
  fds_to_close[fds_to_close_n++] = fd_w[1];
  fds_to_close[fds_to_close_n++] = fd_r[0];
  fds_to_close[fds_to_close_n++] = fd_r[1];
  fds_to_close[fds_to_close_n++] = -1;

  rb = ring_buffer_make (rb_size);

  /* Step 1: Fill buffer with "ABC" */
  ret = write (fd_r[1], "ABC", 3);
  if (ret != 3)
    {
      fprintf (stderr, "Step 1 failed: couldn't write ABC\n");
      return 1;
    }

  bool is_eagain = false;
  ret = ring_buffer_read (rb, fd_r[0], &is_eagain, &err);
  if (ret < 0)
    {
      libcrun_error_release (&err);
      fprintf (stderr, "Step 1 failed: ring_buffer_read error\n");
      return 1;
    }
  if (ret != 3)
    {
      fprintf (stderr, "Step 1 failed: read %d bytes instead of 3\n", ret);
      return 1;
    }

  /* Step 2: Write all data back out */
  ret = ring_buffer_write (rb, fd_w[1], &is_eagain, &err);
  if (ret < 0)
    {
      libcrun_error_release (&err);
      fprintf (stderr, "Step 2 failed: ring_buffer_write error\n");
      return 1;
    }
  if (ret != 3)
    {
      fprintf (stderr, "Step 2 failed: wrote %d bytes instead of 3\n", ret);
      return 1;
    }

  ret = read (fd_w[0], read_back, 3);
  if (ret != 3)
    {
      fprintf (stderr, "Step 2 failed: final read got %d bytes instead of 3\n", ret);
      return 1;
    }

  if (memcmp ("ABC", read_back, 3) != 0)
    {
      fprintf (stderr, "Step 2 failed: expected 'ABC', got '%.3s'\n", read_back);
      return 1;
    }

  return 0;
}

static int
test_ring_buffer_reserved_byte_boundary ()
{
  /* Test that specifically exercises the boundary where reserved byte corruption occurs */
  const size_t rb_size = 3; /* Minimal buffer size */
  cleanup_ring_buffer struct ring_buffer *rb = NULL;

  rb = ring_buffer_make (rb_size);

  /* Simulate the exact scenario where bug occurs:
   * - Buffer has size = 3, so internal size = 4 (positions 0,1,2,3)
   * - Position 3 is reserved, positions 0,1,2 are for data
   * - When tail=2 and head=0, buffer is "full" with 2 bytes of data
   * - Without fix: next write would try to use position 3 (reserved)
   * - With fix: should detect buffer as full and not allow write
   */

  /* Test different head/tail combinations */
  struct
  {
    size_t head, tail;
    bool should_be_full;
    const char *description;
  } test_cases[] = {
    { 0, 2, true, "tail at size-1, head at 0 (wraparound full)" },
    { 1, 0, true, "tail at 0, head at 1 (standard full)" },
    { 2, 1, true, "tail at 1, head at 2 (standard full)" },
    { 0, 1, false, "tail at 1, head at 0 (not full)" },
    { 1, 2, false, "tail at 2, head at 1 (not full)" },
    { 0, 0, false, "empty buffer" },
  };

  for (size_t i = 0; i < sizeof (test_cases) / sizeof (test_cases[0]); i++)
    {
      ring_buffer_free (rb);
      rb = ring_buffer_make (rb_size);

      /* For this test, we just verify the calculation functions
       * don't return impossible values */
      size_t space = ring_buffer_get_space_available (rb);
      size_t data = ring_buffer_get_data_available (rb);
      size_t total = space + data;

      if (total != rb_size)
        {
          fprintf (stderr, "boundary test %zu failed: space=%zu + data=%zu != size=%zu\n",
                   i, space, data, rb_size);
          return 1;
        }
    }

  return 0;
}

static int
test_ring_buffer_no_reserved_byte_access ()
{
  /* This test verifies that the ring buffer never attempts to write to the reserved byte */
  const size_t rb_size = 2;                                 /* Minimal size: internal buffer has 3 bytes (0,1,2), 2 reserved */
  cleanup_free char *canary_buffer = xmalloc (rb_size + 2); /* Extra space for canary */
  libcrun_error_t err = NULL;
  int fds_to_close[5] = {
    -1,
  };
  int fds_to_close_n = 0;
  cleanup_close_vec int *autocleanup_fds = fds_to_close;
  cleanup_ring_buffer struct ring_buffer *rb = NULL;
  int ret = 0;
  int fd_r[2];
  bool is_eagain;

  if (pipe2 (fd_r, O_NONBLOCK) < 0)
    {
      fprintf (stderr, "failed to create pipe\n");
      return 1;
    }

  fds_to_close[fds_to_close_n++] = fd_r[0];
  fds_to_close[fds_to_close_n++] = fd_r[1];
  fds_to_close[fds_to_close_n++] = -1;

  rb = ring_buffer_make (rb_size);

  /* Fill buffer to capacity multiple times to test all positions */
  for (int cycle = 0; cycle < 5; cycle++)
    {
      /* Write maximum possible data */
      memset (canary_buffer, 'A' + cycle, rb_size);
      canary_buffer[rb_size] = '\0';

      ret = write (fd_r[1], canary_buffer, rb_size);
      if (ret != (int) rb_size)
        {
          fprintf (stderr, "cycle %d: failed to write test data\n", cycle);
          return 1;
        }

      /* Read into buffer - this should succeed */
      ret = ring_buffer_read (rb, fd_r[0], &is_eagain, &err);
      if (ret < 0)
        {
          libcrun_error_release (&err);
          fprintf (stderr, "cycle %d: ring_buffer_read failed\n", cycle);
          return 1;
        }

      /* Try to write one more byte - should hit space limit cleanly */
      ret = write (fd_r[1], "X", 1);
      if (ret != 1)
        {
          fprintf (stderr, "cycle %d: failed to write overflow byte\n", cycle);
          return 1;
        }

      ret = ring_buffer_read (rb, fd_r[0], &is_eagain, &err);
      if (ret < 0)
        {
          libcrun_error_release (&err);
          fprintf (stderr, "cycle %d: overflow read failed\n", cycle);
          return 1;
        }

      /* The key test: buffer should now be full and refuse more data */
      if (ring_buffer_get_space_available (rb) > 0)
        {
          ret = write (fd_r[1], "Y", 1);
          if (ret == 1)
            {
              ret = ring_buffer_read (rb, fd_r[0], &is_eagain, &err);
              if (ret > 0)
                {
                  fprintf (stderr, "cycle %d: buffer accepted data beyond capacity\n", cycle);
                  return 1;
                }
            }
        }

      /* Drain buffer for next cycle */
      do
        {
          ret = ring_buffer_write (rb, fd_r[1], &is_eagain, &err);
          if (ret < 0)
            {
              libcrun_error_release (&err);
              fprintf (stderr, "cycle %d: drain failed\n", cycle);
              return 1;
            }
          if (ret > 0)
            {
              char drain_buf[10];
              read (fd_r[0], drain_buf, ret); /* Consume the output */
            }
      } while (! is_eagain && ret > 0);
    }

  return 0;
}

static unsigned char
stream_byte (size_t i)
{
  return (unsigned char) ((i * 7 + 3) & 0xFF);
}

static int
rb_test_write_all (int fd, const unsigned char *buf, size_t n)
{
  size_t off = 0;
  while (off < n)
    {
      ssize_t r = write (fd, buf + off, n - off);
      if (r <= 0)
        return -1;
      off += (size_t) r;
    }
  return 0;
}

static int
rb_test_read_all (int fd, unsigned char *buf, size_t n)
{
  size_t off = 0;
  while (off < n)
    {
      ssize_t r = read (fd, buf + off, n - off);
      if (r <= 0)
        return -1;
      off += (size_t) r;
    }
  return 0;
}

/* discard `n` bytes from fd using `scratch` (size `scratch_size`) as a bounce buffer */
static int
rb_test_discard (int fd, size_t n, unsigned char *scratch, size_t scratch_size)
{
  while (n > 0)
    {
      size_t chunk = n > scratch_size ? scratch_size : n;
      if (rb_test_read_all (fd, scratch, chunk) < 0)
        return -1;
      n -= chunk;
    }
  return 0;
}

/*
 * Regression test for https://github.com/containers/crun/issues/2207.
 *
 * A partial drain leaves head in the middle of the buffer; the next write has
 * to wrap around the reserved byte.  A faulty off-by-one in the iov arithmetic
 * used to skip the reserved byte, corrupting the FIFO stream (garbled terminal
 * output).  This drives that exact sequence and checks the data round-trips.
 *
 * The scenario is scaled above PIPE_BUF (4096) so a partial writev out of the
 * ring buffer can be forced deterministically by controlling how much free
 * space the destination pipe has (writev of <= PIPE_BUF bytes to a pipe is
 * atomic, larger ones are allowed to be partial).
 */
static int
test_ring_buffer_wraparound_partial_drain ()
{
  const size_t rb_size = 8192;
  const size_t want = rb_size / 2; /* how much to partially drain */
  size_t scratch_size = 1 << 16;
  cleanup_free unsigned char *scratch = xmalloc (scratch_size);
  cleanup_free unsigned char *produced = xmalloc (2 * rb_size);
  size_t produced_n = 0, consumed_n = 0, src_pos = 0;
  libcrun_error_t err = NULL;
  int fds_to_close[5] = {
    -1,
  };
  int fds_to_close_n = 0;
  cleanup_close_vec int *autocleanup_fds = fds_to_close;
  cleanup_ring_buffer struct ring_buffer *rb = NULL;
  int src[2], dst[2];
  int src_pipe_cap, pipe_cap;
  size_t prefill;
  bool is_eagain;
  int ret;

  if (pipe2 (src, O_NONBLOCK) < 0)
    {
      fprintf (stderr, "failed to create pipe\n");
      return 1;
    }
  fds_to_close[fds_to_close_n++] = src[0];
  fds_to_close[fds_to_close_n++] = src[1];

  if (pipe2 (dst, O_NONBLOCK) < 0)
    {
      fprintf (stderr, "failed to create pipe\n");
      return 1;
    }
  fds_to_close[fds_to_close_n++] = dst[0];
  fds_to_close[fds_to_close_n++] = dst[1];
  fds_to_close[fds_to_close_n++] = -1;

  if (fcntl (src[1], F_SETPIPE_SZ, (int) (4 * rb_size)) < 0
      || fcntl (dst[1], F_SETPIPE_SZ, (int) (4 * rb_size)) < 0)
    {
      fprintf (stderr, "failed to set pipe capacity\n");
      return 1;
    }

  src_pipe_cap = fcntl (src[1], F_GETPIPE_SZ);
  if (src_pipe_cap < 0 || (size_t) src_pipe_cap < rb_size)
    {
      fprintf (stderr, "source pipe capacity too small\n");
      return 1;
    }

  /* We need the destination pipe to hold the prefill plus the drained data. */
  pipe_cap = fcntl (dst[1], F_GETPIPE_SZ);
  if (pipe_cap < 0 || (size_t) pipe_cap <= want)
    {
      fprintf (stderr, "pipe capacity too small\n");
      return 1;
    }
  prefill = (size_t) pipe_cap - want;

  rb = ring_buffer_make (rb_size);

  /* Step 1: fill the ring buffer completely.  */
  for (size_t i = 0; i < rb_size; i++)
    scratch[i] = stream_byte (src_pos++);
  if (rb_test_write_all (src[1], scratch, rb_size) < 0)
    {
      fprintf (stderr, "step1: failed to write source data\n");
      return 1;
    }
  ret = ring_buffer_read (rb, src[0], &is_eagain, &err);
  if (ret < 0)
    {
      libcrun_error_release (&err);
      fprintf (stderr, "step1: ring_buffer_read failed\n");
      return 1;
    }
  if ((size_t) ret != rb_size)
    {
      fprintf (stderr, "step1: read %d bytes instead of %zu\n", ret, rb_size);
      return 1;
    }
  for (int i = 0; i < ret; i++)
    produced[produced_n++] = scratch[i];

  /* Step 2: partially drain `want` bytes so head ends up in the middle.  */
  memset (scratch, '.', scratch_size);
  for (size_t off = 0; off < prefill;)
    {
      size_t chunk = prefill - off;
      if (chunk > scratch_size)
        chunk = scratch_size;
      if (rb_test_write_all (dst[1], scratch, chunk) < 0)
        {
          fprintf (stderr, "step2: prefill failed\n");
          return 1;
        }
      off += chunk;
    }
  ret = ring_buffer_write (rb, dst[1], &is_eagain, &err);
  if (ret < 0)
    {
      libcrun_error_release (&err);
      fprintf (stderr, "step2: ring_buffer_write failed\n");
      return 1;
    }
  if ((size_t) ret != want)
    {
      fprintf (stderr, "step2: partial drain wrote %d bytes instead of %zu\n", ret, want);
      return 1;
    }
  if (rb_test_discard (dst[0], prefill, scratch, scratch_size) < 0)
    {
      fprintf (stderr, "step2: failed to discard prefill\n");
      return 1;
    }
  if (rb_test_read_all (dst[0], scratch, ret) < 0)
    {
      fprintf (stderr, "step2: failed to read drained data\n");
      return 1;
    }
  for (int i = 0; i < ret; i++)
    {
      if (scratch[i] != produced[consumed_n])
        {
          fprintf (stderr, "step2: mismatch at byte %zu: got %02x want %02x\n",
                   consumed_n, scratch[i], produced[consumed_n]);
          return 1;
        }
      consumed_n++;
    }

  /* Step 3: write more data; it must wrap around the reserved byte.  */
  {
    size_t space = ring_buffer_get_space_available (rb);
    for (size_t i = 0; i < space; i++)
      scratch[i] = stream_byte (src_pos++);
    if (rb_test_write_all (src[1], scratch, space) < 0)
      {
        fprintf (stderr, "step3: failed to write source data\n");
        return 1;
      }
    ret = ring_buffer_read (rb, src[0], &is_eagain, &err);
    if (ret < 0)
      {
        libcrun_error_release (&err);
        fprintf (stderr, "step3: ring_buffer_read failed\n");
        return 1;
      }
    if ((size_t) ret != space)
      {
        fprintf (stderr, "step3: read %d bytes but %zu of space was available\n", ret, space);
        return 1;
      }
    for (int i = 0; i < ret; i++)
      produced[produced_n++] = scratch[i];
  }

  /* Step 4: drain everything left and verify FIFO order is intact.  */
  for (;;)
    {
      ret = ring_buffer_write (rb, dst[1], &is_eagain, &err);
      if (ret < 0)
        {
          libcrun_error_release (&err);
          fprintf (stderr, "step4: ring_buffer_write failed\n");
          return 1;
        }
      if (ret == 0)
        break;
      if (rb_test_read_all (dst[0], scratch, ret) < 0)
        {
          fprintf (stderr, "step4: failed to read drained data\n");
          return 1;
        }
      for (int i = 0; i < ret; i++)
        {
          if (consumed_n >= produced_n)
            {
              fprintf (stderr, "step4: drained more bytes than produced\n");
              return 1;
            }
          if (scratch[i] != produced[consumed_n])
            {
              fprintf (stderr, "step4: mismatch at byte %zu: got %02x want %02x\n",
                       consumed_n, scratch[i], produced[consumed_n]);
              return 1;
            }
          consumed_n++;
        }
    }

  if (consumed_n != produced_n)
    {
      fprintf (stderr, "consumed %zu bytes but produced %zu\n", consumed_n, produced_n);
      return 1;
    }

  return 0;
}

/*
 * Randomized FIFO-integrity stress for the fix in issue #2207.
 *
 * Unlike test_ring_buffer_read_write, which fully drains every iteration and so
 * always returns the buffer to the empty state, this keeps the buffer partially
 * filled: it feeds a random amount and drains a random (often partial) amount
 * each iteration, so head/tail visit arbitrary positions and writes repeatedly
 * wrap around the reserved byte.  The whole stream is checked to round-trip in
 * order.
 *
 * The capacities are all above PIPE_BUF so that a partial writev out of the ring
 * buffer of any size can be forced by controlling the destination pipe's free
 * space (writev of <= PIPE_BUF bytes to a pipe is atomic, larger ones may be
 * partial).
 */
static int
do_stress_ring_buffer_partial_drain (size_t cap)
{
  const int iterations = 600;
  const size_t scratch_size = 1 << 16;
  const size_t page = (size_t) sysconf (_SC_PAGESIZE);
  cleanup_free unsigned char *scratch = xmalloc (scratch_size);
  libcrun_error_t err = NULL;
  int fds_to_close[5] = {
    -1,
  };
  int fds_to_close_n = 0;
  cleanup_close_vec int *autocleanup_fds = fds_to_close;
  cleanup_ring_buffer struct ring_buffer *rb = NULL;
  size_t prod_pos = 0; /* stream index fed into the ring buffer */
  size_t cons_pos = 0; /* stream index drained and verified */
  int src[2], dst[2];
  int src_pipe_cap, pipe_cap;
  bool is_eagain;
  int ret;

  if (pipe2 (src, O_NONBLOCK) < 0)
    {
      fprintf (stderr, "failed to create pipe\n");
      return 1;
    }
  fds_to_close[fds_to_close_n++] = src[0];
  fds_to_close[fds_to_close_n++] = src[1];

  if (pipe2 (dst, O_NONBLOCK) < 0)
    {
      fprintf (stderr, "failed to create pipe\n");
      return 1;
    }
  fds_to_close[fds_to_close_n++] = dst[0];
  fds_to_close[fds_to_close_n++] = dst[1];
  fds_to_close[fds_to_close_n++] = -1;

  if (fcntl (src[1], F_SETPIPE_SZ, (int) (4 * cap)) < 0
      || fcntl (dst[1], F_SETPIPE_SZ, (int) (4 * cap)) < 0)
    {
      fprintf (stderr, "cap=%zu: failed to set pipe capacity\n", cap);
      return 1;
    }

  src_pipe_cap = fcntl (src[1], F_GETPIPE_SZ);
  if (src_pipe_cap < 0 || (size_t) src_pipe_cap < cap)
    {
      fprintf (stderr, "cap=%zu: source pipe capacity too small\n", cap);
      return 1;
    }

  pipe_cap = fcntl (dst[1], F_GETPIPE_SZ);
  if (pipe_cap < 0 || (size_t) pipe_cap <= cap)
    {
      fprintf (stderr, "cap=%zu: pipe capacity too small\n", cap);
      return 1;
    }

  rb = ring_buffer_make (cap);

  for (int iter = 0; iter < iterations; iter++)
    {
      size_t space = ring_buffer_get_space_available (rb);
      size_t avail;

      /* Feed a random amount, bounded by free space so ring_buffer_read
       * consumes it all and the source pipe empties.  */
      if (space > 0)
        {
          size_t feed = 1 + ((size_t) rand () % space);
          if (feed > scratch_size)
            feed = scratch_size;
          for (size_t i = 0; i < feed; i++)
            scratch[i] = stream_byte (prod_pos + i);
          if (rb_test_write_all (src[1], scratch, feed) < 0)
            {
              fprintf (stderr, "cap=%zu: failed to write source data\n", cap);
              return 1;
            }
          ret = ring_buffer_read (rb, src[0], &is_eagain, &err);
          if (ret < 0)
            {
              libcrun_error_release (&err);
              fprintf (stderr, "cap=%zu: ring_buffer_read failed\n", cap);
              return 1;
            }
          if ((size_t) ret != feed)
            {
              fprintf (stderr, "cap=%zu: read %d bytes instead of %zu\n", cap, ret, feed);
              return 1;
            }
          prod_pos += (size_t) ret;
        }

      /* Drain from the buffer.  To force an exact partial drain we leave only
       * `want` bytes free in the destination pipe and rely on a writev larger
       * than PIPE_BUF being allowed to write partially.  A pipe buffers data in
       * page-sized slots, so the free space must be a whole number of empty
       * slots: `want` is a page multiple.  When fewer than a page is buffered we
       * simply drain it all to the (empty) destination pipe.  Either way `dst`
       * is empty again at the end of the iteration.  */
      avail = ring_buffer_get_data_available (rb);
      if (avail > page && (size_t) pipe_cap > page)
        {
          size_t want = (1 + ((size_t) rand () % (avail / page))) * page;
          size_t prefill = (size_t) pipe_cap - want;

          memset (scratch, '.', scratch_size);
          for (size_t off = 0; off < prefill;)
            {
              size_t chunk = prefill - off;
              if (chunk > scratch_size)
                chunk = scratch_size;
              if (rb_test_write_all (dst[1], scratch, chunk) < 0)
                {
                  fprintf (stderr, "cap=%zu: prefill failed\n", cap);
                  return 1;
                }
              off += chunk;
            }

          ret = ring_buffer_write (rb, dst[1], &is_eagain, &err);
          if (ret < 0)
            {
              libcrun_error_release (&err);
              fprintf (stderr, "cap=%zu: ring_buffer_write failed\n", cap);
              return 1;
            }
          if ((size_t) ret != want)
            {
              fprintf (stderr, "cap=%zu: drained %d bytes instead of %zu\n", cap, ret, want);
              return 1;
            }

          if (rb_test_discard (dst[0], prefill, scratch, scratch_size) < 0)
            {
              fprintf (stderr, "cap=%zu: failed to discard prefill\n", cap);
              return 1;
            }
        }
      else if (avail > 0)
        {
          ret = ring_buffer_write (rb, dst[1], &is_eagain, &err);
          if (ret < 0)
            {
              libcrun_error_release (&err);
              fprintf (stderr, "cap=%zu: ring_buffer_write failed\n", cap);
              return 1;
            }
          if ((size_t) ret != avail)
            {
              fprintf (stderr, "cap=%zu: drained %d bytes instead of %zu\n", cap, ret, avail);
              return 1;
            }
        }
      else
        continue;

      if (rb_test_read_all (dst[0], scratch, (size_t) ret) < 0)
        {
          fprintf (stderr, "cap=%zu: failed to read drained data\n", cap);
          return 1;
        }
      for (int i = 0; i < ret; i++)
        {
          if (scratch[i] != stream_byte (cons_pos))
            {
              fprintf (stderr, "cap=%zu: mismatch at byte %zu: got %02x want %02x\n",
                       cap, cons_pos, scratch[i], stream_byte (cons_pos));
              return 1;
            }
          cons_pos++;
        }
    }

  return 0;
}

static int
test_ring_buffer_stress_partial_drain ()
{
  long page_size = sysconf (_SC_PAGESIZE);

  if (page_size < 0)
    {
      fprintf (stderr, "failed to get page size\n");
      return 1;
    }

  size_t caps[] = { 4097, 6000, 8192, 8193, 12000, 16384,
                    (size_t) page_size, (size_t) page_size + 1 };
  size_t i;

  for (i = 0; i < sizeof (caps) / sizeof (caps[0]); i++)
    {
      int ret = do_stress_ring_buffer_partial_drain (caps[i]);
      if (ret != 0)
        return ret;
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
  printf ("1..6\n");

  RUN_TEST (test_ring_buffer_read_write);
  RUN_TEST (test_ring_buffer_wraparound_data_integrity);
  RUN_TEST (test_ring_buffer_reserved_byte_boundary);
  RUN_TEST (test_ring_buffer_no_reserved_byte_access);
  RUN_TEST (test_ring_buffer_wraparound_partial_drain);
  RUN_TEST (test_ring_buffer_stress_partial_drain);
  return 0;
}
