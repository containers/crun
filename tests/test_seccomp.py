#!/bin/env python3
# crun - OCI runtime written in C
#
# Copyright (C) 2021 Giuseppe Scrivano <giuseppe@scrivano.org>
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

import json
import subprocess
import os
import socket
import sys
import array
from tests_utils import *

def is_seccomp_listener_supported():
    r = subprocess.call(["./tests/init", "check-feature", "open_tree"])
    return r == 0

# taken from https://docs.python.org/3/library/socket.html#socket.socket.recvmsg
def recv_fds(sock, msglen, maxfds):
    fds = array.array("i")   # Array of ints
    msg, ancdata, flags, addr = sock.recvmsg(msglen, socket.CMSG_LEN(maxfds * fds.itemsize))
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            # Append data, ignoring any truncated integers at the end.
            fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
    return msg, list(fds)

def test_seccomp_listener():
    if not is_seccomp_listener_supported():
        return 77

    listener_path = "%s/seccomp-listener" % get_tests_root()
    listener_metadata = "SOME-RANDOM-METADATA"

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(listener_path)
    sock.listen(1)

    conf = base_config()
    add_all_namespaces(conf)
    conf['linux']['seccomp'] = {
        'defaultAction': 'SCMP_ACT_ALLOW',
        'listenerPath': listener_path,
        'listenerMetadata': listener_metadata,
    }
    conf['process']['args'] = ['/init', 'true']
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
        conn = sock.accept()
        msg, fds = recv_fds(conn[0], 4096, 1)
        if len(fds) != 1:
            print("invalid number of FDs received", file=sys.stderr)
            return 1

        m = json.loads(msg)
        if m['ociVersion'] != '0.2.0':
            print("invalid OCI version", file=sys.stderr)
            return 1
        if len(m['fds']) != 1:
            print("invalid fds", file=sys.stderr)
            return 1
        if 'pid' not in m != 1:
            print("invalid pid", file=sys.stderr)
            return 1
        if m['metadata'] != listener_metadata:
            print("invalid metadata", file=sys.stderr)
            return 1
        state = m['state']
        if state['status'] != 'creating':
            print("invalid status", file=sys.stderr)
            return 1
        if state['id'] != cid:
            print("invalid container id", file=sys.stderr)
            return 1
        return 0
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        os.unlink(listener_path)

    return -1

all_tests = {
    "seccomp-listener" : test_seccomp_listener,
}

if __name__ == "__main__":
    tests_main(all_tests)
