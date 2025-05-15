/*
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2025 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include "net_device.h"
#include "utils.h"

#include <sys/socket.h>
#include <errno.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <net/if.h>
#if HAVE_STDATOMIC_H
#  include <stdatomic.h>
#  ifndef HAVE_ATOMIC_INT
#    define atomic_uint volatile uint
#  endif
#endif

struct ip_addr
{
  int len;
  int ifa_family;
  int ifa_prefixlen;
  char data[0];
};

struct nl_req
{
  struct nlmsghdr nlh;
  union
  {
    struct ifaddrmsg ifa;
    struct ifinfomsg ifi;
  };
};

static atomic_uint nl_seq_counter;

static uint32_t
get_next_seq ()
{
  return (uint32_t) ++nl_seq_counter;
}

static int
open_netlink_fd (libcrun_error_t *err)
{
  cleanup_close int sock = -1;
  struct sockaddr_nl local = {
    .nl_family = AF_NETLINK
  };
  int fd;

  sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0)
    return crun_make_error (err, errno, "netlink socket");

  if (bind (sock, (struct sockaddr *) &local, sizeof (local)) < 0)
    return crun_make_error (err, errno, "bind");

  fd = sock;
  sock = -1;
  return fd;
}

/* if_nametoindex with an open netlink socket.  */
static int
name_to_index (int sock, const char *ifname, char *buffer, size_t buffer_size, libcrun_error_t *err)
{
  const size_t strlenifname = strlen (ifname);
  struct ifinfomsg *ifi;
  struct rtattr *rta;
  struct nlmsghdr *nlh;
  struct nl_req *req;
  uint32_t seq = get_next_seq ();
  int index = 0;
  ssize_t len;
  int ret;
  struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
  struct iovec iov = { buffer, buffer_size };
  struct msghdr msg = {
    .msg_name = &sa,
    .msg_namelen = sizeof (sa),
    .msg_iov = &iov,
    .msg_iovlen = 1,
  };

  req = (struct nl_req *) buffer;
  memset (req, 0, sizeof (*req));

  ifi = &req->ifi;
  rta = (struct rtattr *) ((char *) ifi + NLMSG_ALIGN (sizeof (*ifi)));
  nlh = &req->nlh;

  nlh->nlmsg_len = NLMSG_LENGTH (sizeof (*ifi));
  nlh->nlmsg_type = RTM_GETLINK;
  nlh->nlmsg_flags = NLM_F_REQUEST;
  nlh->nlmsg_seq = seq;

  ifi->ifi_family = AF_UNSPEC;

  rta->rta_type = IFLA_IFNAME;
  rta->rta_len = RTA_LENGTH (strlenifname + 1);
  memcpy (RTA_DATA (rta), ifname, strlenifname + 1);

  nlh->nlmsg_len += RTA_LENGTH (strlenifname + 1);

  ret = sendmsg (sock, &msg, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "sendmsg");

  len = recvmsg (sock, &msg, 0);
  if (UNLIKELY (len < 0))
    return crun_make_error (err, errno, "recvmsg");

  for (nlh = (struct nlmsghdr *) buffer; NLMSG_OK (nlh, (unsigned int) len); nlh = NLMSG_NEXT (nlh, len))
    {
      if (nlh->nlmsg_seq != seq)
        continue;

      if (nlh->nlmsg_type == NLMSG_ERROR)
        {
          struct nlmsgerr *err_data = (struct nlmsgerr *) NLMSG_DATA (nlh);
          if (err_data->error == 0)
            continue;
          return crun_make_error (err, -err_data->error, "netlink error while looking for interface `%s`", ifname);
        }

      if (nlh->nlmsg_type == RTM_NEWLINK)
        {
          ifi = NLMSG_DATA (nlh);
          index = ifi->ifi_index;
          return index;
        }
    }

  if (index == 0)
    return crun_make_error (err, 0, "could not find device `%s`", ifname);

  return index;
}

static int
wait_for_ack (int sock, uint32_t seq, char *recv_buffer, size_t recv_buffer_size, libcrun_error_t *err)
{
  struct nlmsghdr *nlh_recv = (struct nlmsghdr *) recv_buffer;
  ssize_t len;

  do
    {
      len = recv (sock, recv_buffer, recv_buffer_size, 0);
      if (len < 0)
        return crun_make_error (err, errno, "recv");
  } while (nlh_recv->nlmsg_seq != seq);

  if (! NLMSG_OK (nlh_recv, len))
    return crun_make_error (err, 0, "received invalid packet");

  if (nlh_recv->nlmsg_type == NLMSG_ERROR)
    {
      struct nlmsgerr *err_data = (struct nlmsgerr *) NLMSG_DATA (nlh_recv);
      if (err_data->error == 0)
        return 0;
      return crun_make_error (err, -err_data->error, "netlink error");
    }

  return crun_make_error (err, 0, "internal error: received unknown netlink packet type");
}

static int
get_ip_addresses (int sock, uint32_t seq, uint32_t ifindex, char **out_ips, char *buffer, size_t buffer_size, libcrun_error_t *err)
{
  cleanup_free char *ips = NULL;
  size_t ips_len = 0;
  struct ip_addr *ip;
  ssize_t len;

  while ((len = recv (sock, buffer, buffer_size, 0)) > 0)
    {
      struct ifaddrmsg *ifa;
      struct nlmsghdr *nlh;
      struct rtattr *rta;
      int rta_len;

      nlh = (struct nlmsghdr *) buffer;

      while (NLMSG_OK (nlh, len))
        {
          if (nlh->nlmsg_seq != seq)
            continue;

          if (nlh->nlmsg_type == NLMSG_DONE)
            {
              *out_ips = ips;
              ips = NULL;
              return 0;
            }

          if (nlh->nlmsg_type == NLMSG_ERROR)
            {
              struct nlmsgerr *err_data = (struct nlmsgerr *) NLMSG_DATA (nlh);
              if (err_data->error == 0)
                continue;
              return crun_make_error (err, -err_data->error, "netlink error reading ip addresses");
            }

          ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);
          if (ifa->ifa_index != ifindex)
            {
              nlh = NLMSG_NEXT (nlh, len);
              continue;
            }

          rta_len = IFA_PAYLOAD (nlh);

          for (rta = IFA_RTA (ifa); RTA_OK (rta, rta_len); rta = RTA_NEXT (rta, rta_len))
            {
              if (rta->rta_type == IFA_ADDRESS)
                {
                  size_t new_size = sizeof (*ip) + rta_len;

                  /* Always append an empty struct.  */
                  ips = xrealloc (ips, ips_len + new_size + sizeof (struct ip_addr));

                  ip = (struct ip_addr *) (ips + ips_len);
                  ips_len += new_size;

                  ip->len = rta_len;
                  ip->ifa_family = ifa->ifa_family;
                  ip->ifa_prefixlen = ifa->ifa_prefixlen;
                  memcpy (&(ip->data), RTA_DATA (rta), rta_len);

                  /* Mark the end of the array.  */
                  ip = (struct ip_addr *) (ips + ips_len);
                  ip->len = 0;
                }
            }
          nlh = NLMSG_NEXT (nlh, len);
        }
    }
  if (UNLIKELY (len < 0))
    return crun_make_error (err, errno, "recv");
  return 0;
}

static int
addattr (struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t data_len, libcrun_error_t *err)
{
  int len = RTA_LENGTH (data_len);
  struct rtattr *rta;

  if (NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len) > maxlen)
    return crun_make_error (err, E2BIG, "internal error: buffer too small");

  rta = (struct rtattr *) (((char *) n) + NLMSG_ALIGN (n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  if (data_len)
    memcpy (RTA_DATA (rta), data, data_len);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + RTA_ALIGN (len);
  return 0;
}

static int
configure_ips (int sock, int ifindex, char *buffer, size_t buffer_size, const char *ips, libcrun_error_t *err)
{
  struct ip_addr *ip;
  struct nl_req *req = (struct nl_req *) buffer;
  int ret;

  if (ips == NULL)
    return 0;

  for (ip = (struct ip_addr *) ips; ip->len; ip = (struct ip_addr *) (((char *) ip) + sizeof (*ip) + ip->len))
    {
      req->nlh.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
      req->nlh.nlmsg_type = RTM_NEWADDR;
      req->nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
      req->nlh.nlmsg_seq = get_next_seq ();

      memset (&(req->ifa), 0, sizeof (struct ifaddrmsg));
      req->ifa.ifa_family = ip->ifa_family;
      req->ifa.ifa_prefixlen = ip->ifa_prefixlen;
      req->ifa.ifa_index = ifindex;
      req->ifa.ifa_scope = RT_SCOPE_UNIVERSE;
      req->ifa.ifa_flags = IFA_F_PERMANENT;

      ret = addattr (&(req->nlh), buffer_size, IFA_LOCAL, &ip->data, ip->len, err);
      if (UNLIKELY (ret < 0))
        return ret;
      ret = addattr (&(req->nlh), buffer_size, IFA_ADDRESS, &ip->data, ip->len, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = send (sock, req, req->nlh.nlmsg_len, 0);
      if (ret < 0)
        return crun_make_error (err, errno, "send");

      ret = wait_for_ack (sock, req->nlh.nlmsg_seq, buffer, buffer_size, err);
      if (ret < 0)
        return ret;
    }

  return 0;
}

static void
req_set_link_state (struct nl_req *req, int index, bool up)
{
  memset (req, 0, sizeof (*req));
  req->nlh.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifinfomsg));
  req->nlh.nlmsg_type = RTM_NEWLINK;
  req->nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

  req->ifi.ifi_family = AF_UNSPEC;
  req->ifi.ifi_index = index;

  req->ifi.ifi_flags = up ? IFF_UP : 0;
  req->ifi.ifi_change = IFF_UP;
}

static int
setup_network_device_in_ns (struct nl_req *req, const char *newifname, const char *ips, int netns_fd,
                            char *buffer, size_t buffer_size, libcrun_error_t *err)
{
  cleanup_close int sock_in_ns = -1;
  int ifindex_in_ns;
  int ret;

  ret = setns (netns_fd, CLONE_NEWNET);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "setns to target pid");

  sock_in_ns = open_netlink_fd (err);
  if (sock_in_ns < 0)
    return sock_in_ns;

  ifindex_in_ns = name_to_index (sock_in_ns, newifname, buffer, buffer_size, err);
  if (UNLIKELY (ifindex_in_ns < 0))
    return ifindex_in_ns;

  ret = configure_ips (sock_in_ns, ifindex_in_ns, buffer, buffer_size, ips, err);
  if (ret < 0)
    return ret;

  req_set_link_state (req, ifindex_in_ns, true);
  req->nlh.nlmsg_seq = get_next_seq ();
  ret = send (sock_in_ns, req, req->nlh.nlmsg_len, 0);
  if (ret < 0)
    return crun_make_error (err, errno, "send");

  ret = wait_for_ack (sock_in_ns, req->nlh.nlmsg_seq, buffer, buffer_size, err);
  if (ret < 0)
    return ret;

  return 0;
}

int
move_network_device (const char *ifname, const char *newifname, int netns_fd, libcrun_error_t *err)
{
  const size_t buffer_size = 8192;
  cleanup_free char *ips = NULL;
  cleanup_free char *buffer = xmalloc (buffer_size);
  struct nlmsghdr *nlh;
  struct rtattr *rta;
  struct nl_req *req;
  int ifindex;
  int ret;
  cleanup_close int sock = -1;
  int wait_status;
  pid_t pid;

  sock = open_netlink_fd (err);
  if (sock < 0)
    return sock;

  ifindex = name_to_index (sock, ifname, buffer, buffer_size, err);
  if (UNLIKELY (ifindex < 0))
    return ifindex;

  req = (struct nl_req *) buffer;
  nlh = &req->nlh;

  memset (req, 0, sizeof (*req));
  req->nlh.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifaddrmsg));
  req->nlh.nlmsg_type = RTM_GETADDR;
  req->nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
  req->ifa.ifa_family = AF_UNSPEC;
  req->nlh.nlmsg_seq = get_next_seq ();
  ret = send (sock, req, req->nlh.nlmsg_len, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "send");

  ret = get_ip_addresses (sock, req->nlh.nlmsg_seq, ifindex, &ips, buffer, buffer_size, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Bring device down.  */
  req_set_link_state (req, ifindex, false);
  req->nlh.nlmsg_seq = get_next_seq ();
  ret = send (sock, req, req->nlh.nlmsg_len, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "send");

  ret = wait_for_ack (sock, req->nlh.nlmsg_seq, buffer, buffer_size, err);
  if (UNLIKELY (ret < 0))
    return ret;

  req->nlh.nlmsg_type = RTM_NEWLINK;
  req->nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req->ifi.ifi_family = AF_UNSPEC;
  req->ifi.ifi_index = ifindex;
  req->nlh.nlmsg_len = NLMSG_LENGTH (sizeof (struct ifinfomsg));
  req->nlh.nlmsg_seq = get_next_seq ();

  rta = (struct rtattr *) (((char *) nlh) + NLMSG_ALIGN (nlh->nlmsg_len));
  rta->rta_type = IFLA_NET_NS_FD;
  rta->rta_len = RTA_LENGTH (sizeof (netns_fd));
  memcpy (RTA_DATA (rta), &netns_fd, sizeof (netns_fd));
  nlh->nlmsg_len = NLMSG_ALIGN (nlh->nlmsg_len) + rta->rta_len;

  rta = (struct rtattr *) (((char *) nlh) + NLMSG_ALIGN (nlh->nlmsg_len));
  rta->rta_type = IFLA_IFNAME;
  rta->rta_len = RTA_LENGTH (strlen (newifname) + 1);
  memcpy (RTA_DATA (rta), newifname, strlen (newifname) + 1);
  nlh->nlmsg_len = NLMSG_ALIGN (nlh->nlmsg_len) + rta->rta_len;
  ret = send (sock, req, req->nlh.nlmsg_len, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "send");

  ret = wait_for_ack (sock, req->nlh.nlmsg_seq, buffer, buffer_size, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* must be vfork to propagate the error from the child proc.  */
  pid = vfork ();
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "vfork");

  if (pid == 0)
    {
      ret = setup_network_device_in_ns (req, newifname, ips, netns_fd, buffer, buffer_size, err);
      if (UNLIKELY (ret < 0))
        _exit (-ret);

      _exit (0);
    }

  ret = waitpid_ignore_stopped (pid, &wait_status, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "waitpid for exec child pid");

  if (wait_status != 0)
    return -get_process_exit_status (wait_status);

  return 0;
}
