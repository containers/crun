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
  struct ifaddrmsg ifa;

  int rta_len;
  char *rta;
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

static uint32_t
reset_request (struct nl_req *req, int type, int flags, int msg_len)
{
  uint32_t seq = get_next_seq ();

  memset (req, 0, sizeof (*req));
  req->nlh.nlmsg_type = type;
  req->nlh.nlmsg_flags = flags;
  req->nlh.nlmsg_len = NLMSG_LENGTH (msg_len);
  req->nlh.nlmsg_seq = seq;

  return seq;
}

static void
cleanup_ip_addrsp (void *p)
{
  struct ip_addr **pp = (struct ip_addr **) p;
  struct ip_addr *ip;
  if (*pp == NULL)
    return;

  for (ip = *pp; ip->rta_len >= 0; ip++)
    free (ip->rta);

  free (*pp);
}

#define cleanup_ip_addrs __attribute__ ((cleanup (cleanup_ip_addrsp)))

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

static int
append_rtattr (struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t data_len, libcrun_error_t *err)
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
send_request (int sock, struct nl_req *req, libcrun_error_t *err)
{
  int ret;

  ret = TEMP_FAILURE_RETRY (send (sock, req, req->nlh.nlmsg_len, 0));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "send");

  return 0;
}

/* if_nametoindex with an open netlink socket.  */
static int
name_to_index (int sock, const char *ifname, char *buffer, size_t buffer_size, libcrun_error_t *err)
{
  struct nlmsghdr *nlh;
  struct nl_req *req;
  uint32_t seq;
  int index = 0;
  ssize_t len;
  int ret;

  req = (struct nl_req *) buffer;

  nlh = &req->nlh;

  seq = reset_request (req, RTM_GETLINK, NLM_F_REQUEST, sizeof (struct ifinfomsg));
  req->ifi.ifi_family = AF_UNSPEC;

  ret = append_rtattr (nlh, buffer_size, IFLA_IFNAME, ifname, strlen (ifname) + 1, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = send_request (sock, req, err);
  if (UNLIKELY (ret < 0))
    return ret;

  len = TEMP_FAILURE_RETRY (recv (sock, buffer, buffer_size, 0));
  if (UNLIKELY (len < 0))
    return crun_make_error (err, errno, "recv");

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
          struct ifinfomsg *ifi = NLMSG_DATA (nlh);
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
      len = TEMP_FAILURE_RETRY (recv (sock, recv_buffer, recv_buffer_size, 0));
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

static void
copy_ip_addr (struct nlmsghdr *nlh, struct ip_addr *ip)
{
  struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);
  memcpy (&ip->ifa, ifa, sizeof (struct ifaddrmsg));
  ip->rta_len = IFA_PAYLOAD (nlh);
  ip->rta = xmalloc (ip->rta_len);
  memcpy (ip->rta, IFA_RTA (ifa), ip->rta_len);
};

static int
get_ip_addresses (int sock, uint32_t ifindex, struct ip_addr **out_ips, char *buffer, size_t buffer_size, libcrun_error_t *err)
{
  struct nl_req *req = (struct nl_req *) buffer;
  cleanup_ip_addrs struct ip_addr *ips = NULL;
  size_t ips_len = 0;
  int optval = 1;
  uint32_t seq;
  ssize_t len;
  int ret;

#ifdef NETLINK_GET_STRICT_CHK
  ret = setsockopt (sock, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &optval, sizeof (optval));
  if (ret < 0)
    {
      if (errno != ENOPROTOOPT)
        return crun_make_error (err, errno, "setsockopt (NETLINK_GET_STRICT_CHK)");

      /* NETLINK_GET_STRICT_CHK not supported by this kernel, continue without strict checking.   */
    }
#endif

  seq = reset_request (req, RTM_GETADDR, NLM_F_DUMP | NLM_F_REQUEST, sizeof (struct ifaddrmsg));
  req->ifa.ifa_family = AF_UNSPEC;
  req->ifa.ifa_index = ifindex;

  ret = send_request (sock, req, err);
  if (UNLIKELY (ret < 0))
    return ret;

  while ((len = TEMP_FAILURE_RETRY (recv (sock, buffer, buffer_size, 0))) > 0)
    {
      struct nlmsghdr *nlh;

      for (nlh = (struct nlmsghdr *) buffer; NLMSG_OK (nlh, len); nlh = NLMSG_NEXT (nlh, len))
        {
          struct ifaddrmsg *ifa;

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
            continue;

          /* Copy only permanent, globally routable IP addresses.  */
          if (! (ifa->ifa_flags & IFA_F_PERMANENT) || (ifa->ifa_scope != RT_SCOPE_UNIVERSE))
            continue;

          /* Always append an empty struct.  */
          ips = xrealloc (ips, sizeof (struct ip_addr) * (++ips_len + 1));
          /* Mark the end of the array.  */
          ips[ips_len].rta_len = -1;

          copy_ip_addr (nlh, &ips[ips_len - 1]);
        }
    }
  if (UNLIKELY (len < 0))
    return crun_make_error (err, errno, "recv");
  return 0;
}

static int
configure_ip_addresses (int sock, int ifindex, char *buffer, size_t buffer_size, const struct ip_addr *ips, libcrun_error_t *err)
{
  struct nl_req *req = (struct nl_req *) buffer;
  const struct ip_addr *ip;
  int ret;

  if (ips == NULL)
    return 0;

  for (ip = ips; ip->rta_len >= 0; ip++)
    {
      /* RTA_NEXT modifies the argument, so use a copy.  */
      int rta_len = ip->rta_len;
      struct rtattr *rta;
      uint32_t seq;

      seq = reset_request (req, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK, sizeof (struct ifaddrmsg));

      memcpy (&req->ifa, &ip->ifa, sizeof (struct ifaddrmsg));

      req->ifa.ifa_index = ifindex;

      for (rta = (struct rtattr *) ip->rta; RTA_OK (rta, rta_len); rta = RTA_NEXT (rta, rta_len))
        {
          ret = append_rtattr (&(req->nlh), buffer_size, rta->rta_type, RTA_DATA (rta), RTA_PAYLOAD (rta), err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = send_request (sock, req, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = wait_for_ack (sock, seq, buffer, buffer_size, err);
      if (ret < 0)
        return ret;
    }

  return 0;
}

static int
request_enable_interface_and_wait (int sock, char *buffer, size_t buffer_size, int index, libcrun_error_t *err)
{
  struct nl_req *req = (struct nl_req *) buffer;
  uint32_t seq;
  int ret;

  seq = reset_request (req, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sizeof (struct ifinfomsg));

  req->ifi.ifi_family = AF_UNSPEC;
  req->ifi.ifi_index = index;

  req->ifi.ifi_flags = IFF_UP;
  req->ifi.ifi_change = IFF_UP;

  ret = send_request (sock, req, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return wait_for_ack (sock, seq, buffer, buffer_size, err);
}

static int
setup_network_device_in_ns_helper (char *buffer, size_t buffer_size, int netns_fd, const char *newifname,
                                   struct ip_addr *ips, libcrun_error_t *err)
{
  cleanup_close int sock_in_ns = -1;
  int new_ifindex;
  int ret;

  ret = setns (netns_fd, CLONE_NEWNET);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "change network namespace");

  sock_in_ns = open_netlink_fd (err);
  if (sock_in_ns < 0)
    return sock_in_ns;

  /* we could ask for a specific index with IFLA_NEW_IFINDEX, and apparently the kernel tries anyway to
     reuse the existing one, but asking for a specific index could cause conflicts if the
     target network namespace already exists, so avoid doing it and lookup the device again.  */
  new_ifindex = name_to_index (sock_in_ns, newifname, buffer, buffer_size, err);
  if (UNLIKELY (new_ifindex < 0))
    return new_ifindex;

  ret = configure_ip_addresses (sock_in_ns, new_ifindex, buffer, buffer_size, ips, err);
  if (ret < 0)
    return ret;

  return request_enable_interface_and_wait (sock_in_ns, buffer, buffer_size, new_ifindex, err);
}

static int
do_move_link_to_ns_and_wait (int sock, char *buffer, size_t buffer_size, int ifindex, int netns_fd, const char *newifname, libcrun_error_t *err)
{
  struct nl_req *req = (struct nl_req *) buffer;
  uint32_t seq;
  int ret;

  seq = reset_request (req, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, sizeof (struct ifinfomsg));
  req->ifi.ifi_family = AF_UNSPEC;
  req->ifi.ifi_index = ifindex;

  ret = append_rtattr (&req->nlh, buffer_size, IFLA_NET_NS_FD, &netns_fd, sizeof (netns_fd), err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = append_rtattr (&req->nlh, buffer_size, IFLA_IFNAME, newifname, strlen (newifname) + 1, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = send_request (sock, req, err);
  if (UNLIKELY (ret < 0))
    return ret;

  return wait_for_ack (sock, seq, buffer, buffer_size, err);
}

int
move_network_device (const char *ifname, const char *newifname, int netns_fd, libcrun_error_t *err)
{
  const size_t buffer_size = 8192;
  cleanup_ip_addrs struct ip_addr *ips = NULL;
  cleanup_free char *buffer = xmalloc (buffer_size);
  cleanup_close int sock = -1;
  int wait_status;
  int ifindex;
  pid_t pid;
  int ret;

  sock = open_netlink_fd (err);
  if (sock < 0)
    return sock;

  ifindex = name_to_index (sock, ifname, buffer, buffer_size, err);
  if (UNLIKELY (ifindex < 0))
    return ifindex;

  ret = get_ip_addresses (sock, ifindex, &ips, buffer, buffer_size, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* Move the device to the target network namespace.  */
  ret = do_move_link_to_ns_and_wait (sock, buffer, buffer_size, ifindex, netns_fd, newifname, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* must be vfork to propagate the error from the child proc.  */
  pid = vfork ();
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "vfork");

  if (pid == 0)
    {
      ret = setup_network_device_in_ns_helper (buffer, buffer_size, netns_fd, newifname, ips, err);
      if (UNLIKELY (ret < 0))
        _safe_exit (-ret);

      _safe_exit (0);
    }

  ret = waitpid_ignore_stopped (pid, &wait_status, 0);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "waitpid for exec child pid");

  if (wait_status != 0)
    return -get_process_exit_status (wait_status);

  return 0;
}
