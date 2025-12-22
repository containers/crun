#!/bin/env python3
# crun - OCI runtime written in C
#
# Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
# crun is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# crun is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with crun.  If not, see <http://www.gnu.org/licenses/>.

import os
import subprocess
import tempfile
import socket
import array
from tests_utils import *


def recv_fds(sock, msglen, maxfds):
    """Receive file descriptors over a UNIX socket."""
    fds = array.array("i")
    msg, ancdata, flags, addr = sock.recvmsg(msglen, socket.CMSG_LEN(maxfds * fds.itemsize))
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
    return msg, list(fds)


def test_annotation_pidfd_receiver():
    """Test run.oci.pidfd_receiver annotation sends pidfd to UNIX socket."""
    if is_rootless():
        return (77, "requires root privileges")

    # Check if pidfds are supported
    try:
        ret = subprocess.call([get_init_path(), "check-feature", "pidfd"])
        if ret != 0:
            return (77, "pidfd not supported")
    except Exception:
        return (77, "pidfd not supported")

    socket_path = os.path.join(get_tests_root(), "pidfd-receiver.sock")

    # Create UNIX socket server
    try:
        if os.path.exists(socket_path):
            os.unlink(socket_path)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(socket_path)
        sock.listen(1)
        sock.settimeout(5.0)  # 5 second timeout

        conf = base_config()
        add_all_namespaces(conf)
        conf['process']['args'] = ['/init', 'pause']

        # Add annotation for pidfd receiver
        if 'annotations' not in conf:
            conf['annotations'] = {}
        conf['annotations']['run.oci.pidfd_receiver'] = socket_path

        cid = None
        try:
            # Start container in detached mode
            _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

            # Accept connection and receive pidfd
            conn, addr = sock.accept()
            conn.settimeout(2.0)

            # Receive the pidfd
            msg, fds = recv_fds(conn, 1024, 1)

            if len(fds) != 1:
                logger.info("pidfd_receiver: expected 1 FD, got %d", len(fds))
                return -1

            pidfd = fds[0]
            logger.info("pidfd_receiver: successfully received pidfd %d", pidfd)

            # Close the received pidfd
            os.close(pidfd)
            conn.close()

            return 0

        except socket.timeout:
            logger.info("pidfd_receiver: timeout waiting for connection")
            return -1
        except Exception as e:
            logger.info("pidfd_receiver: exception: %s", e)
            return -1
        finally:
            if cid is not None:
                try:
                    run_crun_command(["delete", "-f", cid])
                except Exception:
                    pass
    except Exception as e:
        logger.info("pidfd_receiver: socket setup failed: %s", e)
        return -1
    finally:
        try:
            sock.close()
        except Exception:
            pass
        try:
            if os.path.exists(socket_path):
                os.unlink(socket_path)
        except Exception:
            pass


all_tests = {
    "annotation-pidfd-receiver": test_annotation_pidfd_receiver,
}

if __name__ == "__main__":
    tests_main(all_tests)
