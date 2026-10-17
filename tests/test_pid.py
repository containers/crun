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

import json
import os
import shutil
import subprocess
import tempfile
from tests_utils import *

def test_pid():
    if is_rootless():
        return (77, "requires root privileges")
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    conf['linux']['namespaces'].append({"type" : "pid"})
    out, _ = run_and_get_output(conf, hide_stderr=True)
    pid = parse_proc_status(out)['Pid']
    if pid == "1":
        return 0
    return -1

def test_pid_user():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    pid = parse_proc_status(out)['Pid']
    if pid == "1":
        return 0
    return -1

def test_pid_host_namespace():
    if is_rootless():
        return (77, "requires root privileges")
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    # No PID namespace is added.  Expect PID to not be 1.
    out, _ = run_and_get_output(conf, hide_stderr=True)
    pid = parse_proc_status(out)['Pid']
    if pid != "1":
        return 0
    return -1

def test_pid_ppid_is_zero():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    status = parse_proc_status(out)
    pid = status.get('Pid')
    ppid = status.get('PPid')
    if pid == "1" and ppid == "0":
        return 0
    return -1

def join_pid_namespace(userns=False, hooks=False):
    if is_rootless():
        return (77, "requires root privileges")
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    cwd = os.getcwd()
    current_mntns = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        state = json.loads(run_crun_command(["state", cid]))
        pidns = "/proc/%d/ns/pid" % state['pid']

        # With a user namespace, nosuid and nodev on the bundle are locked, so
        # the rootfs cannot be made read-only with mount_setattr() and the
        # fallback through /proc/self/fd is used.
        if userns:
            current_mntns = os.open("/proc/self/ns/mnt", os.O_RDONLY)
            os.unshare(os.CLONE_NEWNS)
            subprocess.check_call(["mount", "--make-rslave", "/"])
            if subprocess.call(["mount", "-t", "tmpfs", "-o", "nosuid,nodev", "tmpfs", get_tests_root()]) != 0:
                return (77, "cannot mount tmpfs")

        conf = base_config()
        add_all_namespaces(conf, pidns=False, userns=userns)
        conf['linux']['namespaces'].append({"type" : "pid", "path" : pidns})
        if hooks:
            conf['hooks'] = {"createContainer" : [{"path" : get_init_path(), "args" : ["init", "true"]}]}

        conf['process']['args'] = ['/init', 'readlink', '/proc/self/ns/pid']
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if out.strip() != os.readlink(pidns):
            logger.info("expected PID namespace %s, got %s", os.readlink(pidns), out)
            return -1

        # The proc file system must be the one of the joined PID namespace.
        conf['process']['args'] = ['/init', 'cat', '/proc/1/cmdline']
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if "pause" not in out:
            logger.info("PID 1 is not the init process of the joined PID namespace: %s", out)
            return -1
    finally:
        if current_mntns is not None:
            # setns() changes the working directory to the root of the namespace.
            os.setns(current_mntns, os.CLONE_NEWNS)
            os.close(current_mntns)
            os.chdir(cwd)
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_pid_join_namespace_hooks_pid():
    if is_rootless():
        return (77, "requires root privileges")
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    state_dir = tempfile.mkdtemp()
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        state = json.loads(run_crun_command(["state", cid]))
        pidns = "/proc/%d/ns/pid" % state['pid']

        conf = base_config()
        add_all_namespaces(conf, pidns=False)
        conf['linux']['namespaces'].append({"type" : "pid", "path" : pidns})
        hook_names = ["prestart", "createRuntime"]
        conf['hooks'] = {}
        for name in hook_names:
            script = "pid=$(grep -o '\"pid\": *[0-9]*' | grep -o '[0-9]*$'); readlink /proc/$pid/ns/pid > %s" % os.path.join(state_dir, name)
            conf['hooks'][name] = [{"path" : "/bin/sh", "args" : ["/bin/sh", "-c", script]}]

        conf['process']['args'] = ['/init', 'true']
        run_and_get_output(conf, hide_stderr=True)

        for name in hook_names:
            with open(os.path.join(state_dir, name)) as f:
                ns = f.read().strip()
            if ns != os.readlink(pidns):
                logger.info("%s hook: expected PID namespace %s, got %s", name, os.readlink(pidns), ns)
                return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        shutil.rmtree(state_dir)
    return 0

def test_pid_join_namespace():
    return join_pid_namespace()

def test_pid_join_namespace_userns():
    return join_pid_namespace(userns=True)

def test_pid_join_namespace_hooks():
    return join_pid_namespace(hooks=True)

all_tests = {
    "pid" : test_pid,
    "pid-user" : test_pid_user,
    "pid-host-namespace" : test_pid_host_namespace,
    "pid-ppid-is-zero" : test_pid_ppid_is_zero,
    "pid-join-namespace" : test_pid_join_namespace,
    "pid-join-namespace-userns" : test_pid_join_namespace_userns,
    "pid-join-namespace-hooks" : test_pid_join_namespace_hooks,
    "pid-join-namespace-hooks-pid" : test_pid_join_namespace_hooks_pid,
}

if __name__ == "__main__":
    tests_main(all_tests)
