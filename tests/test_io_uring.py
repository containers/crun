#!/bin/env python3
# crun - OCI runtime written in C
#
# Copyright (C) 2026 Eugene Gvozdetsky <gvozdet@gmail.com>
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
from tests_utils import *

ANNOTATION = "run.oci.io_uring"

POLICY = {
    "ops": ["IORING_OP_NOP", "IORING_OP_READ", "IORING_OP_SOCKET"],
    "socketFamilies": ["AF_INET"],
}

CHECKS = ["nop", "read", "read-async", "write", "socket-inet", "socket-unix"]

EXPECTED = {
    "nop": "allowed",
    "read": "allowed",
    "read-async": "allowed",
    "write": "denied",
    "socket-inet": "allowed",
    "socket-unix": "denied",
}


def io_uring_restrictions_supported():
    return subprocess.call([get_init_path(), "check-feature", "io_uring-restrictions"]) == 0


def policy_config(policy, args, no_new_privileges=True):
    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = args
    conf['process']['noNewPrivileges'] = no_new_privileges
    conf.setdefault('annotations', {})[ANNOTATION] = json.dumps(policy)
    return conf


def check_output(out):
    results = dict(line.split() for line in out.strip().splitlines())
    if results != EXPECTED:
        logger.info("unexpected io_uring results: %s, expected %s", results, EXPECTED)
        return -1
    return 0


def test_io_uring_policy():
    if not io_uring_restrictions_supported():
        return (77, "io_uring restrictions not supported by the kernel")

    # Without no_new_privileges, the filters are registered before the
    # capabilities are dropped, otherwise after.
    for no_new_privileges in [True, False]:
        conf = policy_config(POLICY, ['/init', 'io_uring'] + CHECKS, no_new_privileges)
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if check_output(out) < 0:
            logger.info("failed with noNewPrivileges=%s", no_new_privileges)
            return -1
    return 0


def test_io_uring_policy_exec():
    if not io_uring_restrictions_supported():
        return (77, "io_uring restrictions not supported by the kernel")

    conf = policy_config(POLICY, ['/init', 'pause'])
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        for no_new_privs in ["--no-new-privs", None]:
            args = ["exec"] + ([no_new_privs] if no_new_privs else []) + [cid, "/init", "io_uring"] + CHECKS
            out = run_crun_command(args)
            if check_output(out) < 0:
                logger.info("exec failed with %s", no_new_privs)
                return -1
        return 0
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_io_uring_deny_all():
    if not io_uring_restrictions_supported():
        return (77, "io_uring restrictions not supported by the kernel")

    conf = policy_config({"ops": []}, ['/init', 'io_uring', 'nop', 'read'])
    out, _ = run_and_get_output(conf, hide_stderr=True)
    if out.split() != ["nop", "denied", "read", "denied"]:
        logger.info("unexpected io_uring results: %s", out)
        return -1
    return 0


def test_io_uring_nested():
    if not io_uring_restrictions_supported():
        return (77, "io_uring restrictions not supported by the kernel")

    # crun itself runs under a policy that allows NOP, READ and WRITE: WRITE
    # must stay denied by the container's policy, and SOCKET by the outer one.
    conf = policy_config(POLICY, ['/init', 'io_uring', 'nop', 'read', 'write', 'socket-inet'])
    wrapper = [get_init_path(), 'io_uring-restrict', 'nop,read,write']
    out, _ = run_and_get_output(conf, hide_stderr=True, wrapper=wrapper)
    expected = ["nop", "allowed", "read", "allowed", "write", "denied", "socket-inet", "denied"]
    if out.split() != expected:
        logger.info("unexpected io_uring results: %s", out)
        return -1
    return 0


def test_io_uring_unknown_names():
    if not io_uring_restrictions_supported():
        return (77, "io_uring restrictions not supported by the kernel")

    # Unknown names are ignored, and what they would allow stays denied.
    checks = ['nop', 'read', 'socket-inet', 'socket-unix']
    for policy, expected in [
        ({"ops": ["IORING_OP_NOP", "IORING_OP_FOO", "IORING_OP_SOCKET"], "socketFamilies": ["AF_FOO", "AF_INET"]},
         ["nop", "allowed", "read", "denied", "socket-inet", "allowed", "socket-unix", "denied"]),
        ({"ops": ["IORING_OP_NOP", "IORING_OP_SOCKET"], "socketFamilies": ["AF_FOO"]},
         ["nop", "allowed", "read", "denied", "socket-inet", "denied", "socket-unix", "denied"]),
    ]:
        conf = policy_config(policy, ['/init', 'io_uring'] + checks)
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if out.split() != expected:
            logger.info("unexpected io_uring results for %s: %s", policy, out)
            return -1
    return 0


def test_io_uring_invalid_policy():
    for policy in [
        {"ops": "IORING_OP_READ"},
        {"ops": [], "socketFamilies": []},
        {"ops": ["IORING_OP_READ"], "socketFamilies": ["AF_INET"]},
        {"ops": [], "defaultAction": "deny"},
        {},
    ]:
        conf = policy_config(policy, ['/init', 'true'])
        try:
            run_and_get_output(conf, hide_stderr=False)
        except subprocess.CalledProcessError as e:
            if ANNOTATION.encode() not in e.output:
                logger.info("policy %s failed without mentioning the annotation: %s", policy, e.output)
                return -1
            continue
        logger.info("policy %s was accepted", policy)
        return -1
    return 0


all_tests = {
    "io-uring-policy": test_io_uring_policy,
    "io-uring-policy-exec": test_io_uring_policy_exec,
    "io-uring-deny-all": test_io_uring_deny_all,
    "io-uring-nested": test_io_uring_nested,
    "io-uring-unknown-names": test_io_uring_unknown_names,
    "io-uring-invalid-policy": test_io_uring_invalid_policy,
}

if __name__ == "__main__":
    tests_main(all_tests)
