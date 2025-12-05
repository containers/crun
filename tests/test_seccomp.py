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
    r = subprocess.call([get_init_path(), "check-feature", "open_tree"])
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
        return (77, "seccomp listener not supported")

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
            sys.stderr.write("# seccomp listener test failed: expected 1 FD, got %d\n" % len(fds))
            return -1

        try:
            m = json.loads(msg)
        except json.JSONDecodeError as e:
            sys.stderr.write("# seccomp listener test failed: invalid JSON message: %s\n" % str(e))
            sys.stderr.write("# raw message: %s\n" % msg)
            return -1

        if m.get('ociVersion') != '0.2.0':
            sys.stderr.write("# seccomp listener test failed: expected ociVersion '0.2.0', got '%s'\n" % m.get('ociVersion'))
            return -1
        if len(m.get('fds', [])) != 1:
            sys.stderr.write("# seccomp listener test failed: expected 1 fd in message, got %d\n" % len(m.get('fds', [])))
            return -1
        if 'pid' not in m:
            sys.stderr.write("# seccomp listener test failed: missing 'pid' field in message\n")
            sys.stderr.write("# message fields: %s\n" % list(m.keys()))
            return -1
        if m.get('metadata') != listener_metadata:
            sys.stderr.write("# seccomp listener test failed: expected metadata '%s', got '%s'\n" % (listener_metadata, m.get('metadata')))
            return -1
        state = m.get('state', {})
        if state.get('status') != 'creating':
            sys.stderr.write("# seccomp listener test failed: expected status 'creating', got '%s'\n" % state.get('status'))
            return -1
        if state.get('id') != cid:
            sys.stderr.write("# seccomp listener test failed: expected container id '%s', got '%s'\n" % (cid, state.get('id')))
            return -1
        return 0
    except Exception as e:
        sys.stderr.write("# seccomp listener test failed with exception: %s\n" % str(e))
        if cid is not None:
            sys.stderr.write("# container ID: %s\n" % cid)
        sys.stderr.write("# listener path: %s\n" % listener_path)
        return -1
    finally:
        if cid is not None:
            try:
                run_crun_command(["delete", "-f", cid])
            except Exception as cleanup_e:
                sys.stderr.write("# warning: failed to cleanup container %s: %s\n" % (cid, str(cleanup_e)))
        try:
            os.unlink(listener_path)
        except Exception as cleanup_e:
            sys.stderr.write("# warning: failed to cleanup listener socket %s: %s\n" % (listener_path, str(cleanup_e)))

all_tests = {
    "seccomp-listener" : test_seccomp_listener,
}

if __name__ == "__main__":
    tests_main(all_tests)
