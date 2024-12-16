/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2024 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include <config.h>
#include <sys/uio.h>

#include "ring_buffer.h"
#include "utils.h"

struct ring_buffer
{
  char *buffer;
  size_t size;
  size_t head;
  size_t tail;
};

/*
 * It returns up to two regions in `iov` that can be read from.
 */
static int
ring_buffer_get_read_iov (struct ring_buffer *rb, struct iovec *iov)
{
  int iov_count = 0;

  /* Buffer is empty.  */
  if (rb->head == rb->tail)
    return 0;

  /* Head before tail.  There is only one region to read from, up to tail.  */
  if (rb->tail > rb->head)
    {
      iov[iov_count].iov_base = rb->buffer + rb->head;
      iov[iov_count].iov_len = rb->tail - rb->head;
      iov_count++;
    }
  /* Head after tail.  There are two regions to read from, up to the
   * end of the buffer and from the beginning of the buffer to tail.  */
  else
    {
      iov[iov_count].iov_base = rb->buffer + rb->head;
      iov[iov_count].iov_len = rb->size - rb->head;
      iov_count++;

      if (rb->tail > 0)
        {
          iov[iov_count].iov_base = rb->buffer;
          iov[iov_count].iov_len = rb->tail;
          iov_count++;
        }
    }
  return iov_count;
}

/*
 * It returns up to two regions in `iov` that can be written to without overwriting
 * existing data.
 */
static int
ring_buffer_get_write_iov (struct ring_buffer *rb, struct iovec *iov)
{
  int iov_count = 0;

  /* Buffer is full.  */
  if (rb->tail + 1 == rb->head)
    return 0;

  /* Tail before head.  There is only one region to write to, up to head.  */
  if (rb->head > rb->tail + 1)
    {
      iov[iov_count].iov_base = rb->buffer + rb->tail;
      iov[iov_count].iov_len = rb->head - rb->tail - 1;
      iov_count++;
    }
  /* Tail after or equal to head.  There are two regions to write to, up to the
   * end of the buffer and from the beginning of the buffer to head.  */
  else
    {
      iov[iov_count].iov_base = rb->buffer + rb->tail;
      iov[iov_count].iov_len = rb->size - rb->tail;
      iov_count++;

      if (rb->head > 1)
        {
          iov[iov_count].iov_base = rb->buffer;
          iov[iov_count].iov_len = rb->head - 1;
          iov_count++;
        }
    }
  return iov_count;
}

/* manually advance the head after a successful read.  */
static void
ring_buffer_advance_nocheck_head (struct ring_buffer *rb, size_t amount)
{
  rb->head = (rb->head + amount) % rb->size;
}

/* manually advance the tail after a successful write.  */
static void
ring_buffer_advance_nocheck_tail (struct ring_buffer *rb, size_t amount)
{
  rb->tail = (rb->tail + amount) % rb->size;
}

size_t
ring_buffer_get_data_available (struct ring_buffer *rb)
{
  if (rb->head <= rb->tail)
    return rb->tail - rb->head;

  return rb->size - rb->head + rb->tail;
}

size_t
ring_buffer_get_size (struct ring_buffer *rb)
{
  return rb->size - 1;
}

size_t
ring_buffer_get_space_available (struct ring_buffer *rb)
{
  return rb->size - ring_buffer_get_data_available (rb) - 1;
}

int
ring_buffer_read (struct ring_buffer *rb, int fd, bool *is_eagain, libcrun_error_t *err)
{
  struct iovec iov[2];
  int iov_count = 0;
  ssize_t ret;

  *is_eagain = false;

  iov_count = ring_buffer_get_write_iov (rb, iov);
  if (iov_count == 0)
    {
      *is_eagain = true;
      return 0;
    }

  ret = readv (fd, iov, iov_count);
  if (UNLIKELY (ret < 0))
    {
      if (errno == EIO)
        return 0;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          *is_eagain = true;
          return 0;
        }
      return crun_make_error (err, errno, "readv");
    }
  ring_buffer_advance_nocheck_tail (rb, ret);
  return ret;
}

int
ring_buffer_write (struct ring_buffer *rb, int fd, bool *is_eagain, libcrun_error_t *err)
{
  ssize_t ret;
  struct iovec iov[2];
  int iov_count = 0;

  *is_eagain = false;

  iov_count = ring_buffer_get_read_iov (rb, iov);
  if (iov_count == 0)
    {
      *is_eagain = true;
      return 0;
    }

  ret = writev (fd, iov, iov_count);
  if (UNLIKELY (ret < 0))
    {
      if (errno == EIO)
        return 0;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          *is_eagain = true;
          return 0;
        }
      return crun_make_error (err, errno, "writev");
    }
  ring_buffer_advance_nocheck_head (rb, ret);
  /* If the buffer is empty, reset the head and tail.  */
  if (rb->head == rb->tail)
    {
      rb->head = 0;
      rb->tail = 0;
    }
  return ret;
}

struct ring_buffer *
ring_buffer_make (size_t size)
{
  struct ring_buffer *rb = xmalloc (sizeof (struct ring_buffer));

  /* The extra byte is used to distinguish between full and empty buffer.  */
  rb->size = size + 1;
  rb->buffer = xmalloc (rb->size);
  rb->head = 0;
  rb->tail = 0;

  return rb;
}

void
ring_buffer_free (struct ring_buffer *rb)
{
  if (rb == NULL)
    return;
  free (rb->buffer);
  free (rb);
}
