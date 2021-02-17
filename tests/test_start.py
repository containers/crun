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

import time
import json
import subprocess
import os
import os.path
import shutil
import sys
import threading
import socket
from tests_utils import *

def test_cwd_relative():
    conf = base_config()
    conf['process']['args'] = ['./init', 'echo', 'hello']
    conf['process']['cwd'] = "/sbin"
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf)
        if "hello" not in str(out):
            return -1
    except Exception as e:
        return -1
    return 0

def test_cwd_relative_subdir():
    conf = base_config()
    conf['process']['args'] = ['sbin/init', 'echo', 'hello']
    conf['process']['cwd'] = "/"
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf)
        if "hello" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_cwd_absolute():
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'hello']
    conf['process']['cwd'] = "/sbin"
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf)
        if "hello" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_start():
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'hello']
    add_all_namespaces(conf)
    cid = None
    try:
        proc, cid = run_and_get_output(conf, command='create', use_popen=True)
        for i in range(50):
            try:
                s = run_crun_command(["state", cid])
                break
            except Exception as e:
                time.sleep(0.1)

        run_crun_command(["start", cid])
        out, _ = proc.communicate()
        if "hello" not in str(out):
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_start_override_config():
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'hello']
    add_all_namespaces(conf)
    cid = None
    try:
        proc, cid = run_and_get_output(conf, command='create', use_popen=True, relative_config_path="config/config.json")
        for i in range(50):
            try:
                s = run_crun_command(["state", cid])
                break
            except Exception as e:
                time.sleep(0.1)

        run_crun_command(["start", cid])
        out, _ = proc.communicate()
        if "hello" not in str(out):
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0


def test_run_twice():
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'hi']
    add_all_namespaces(conf)
    try:
        id_container = "container-%s" % os.getpid()
        for i in range(2):
            out, cid = run_and_get_output(conf, command='run', id_container=id_container)
            if "hi" not in str(out):
                return -1
    except:
        return -1
    return 0

def test_sd_notify():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    env = dict(os.environ)
    env["NOTIFY_SOCKET"] = "/run/notify/the-socket"
    try:
        out, cid = run_and_get_output(conf, env=env, command='run')
        if "/run/notify/the-socket" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_sd_notify_file():
    conf = base_config()
    conf['process']['args'] = ['/init', 'ls', '/tmp/parent-dir/the-socket/']
    add_all_namespaces(conf)
    env = dict(os.environ)
    env["NOTIFY_SOCKET"] = "/tmp/parent-dir/the-socket"
    try:
        out, cid = run_and_get_output(conf, env=env, command='run')
        if "notify" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_sd_notify_env():
    conf = base_config()
    conf['process']['args'] = ['/init', 'printenv', 'NOTIFY_SOCKET']
    add_all_namespaces(conf)
    env = dict(os.environ)
    env["NOTIFY_SOCKET"] = "/tmp/parent-dir/the-socket"
    try:
        out, cid = run_and_get_output(conf, env=env, command='run')
        if "/tmp/parent-dir/the-socket/notify" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_sd_notify_proxy():
    if os.getuid() != 0:
        return 77

    has_open_tree_status = subprocess.call(["./tests/init", "check-feature", "open_tree"])
    has_move_mount_status = subprocess.call(["./tests/init", "check-feature", "move_mount"])
    if has_open_tree_status != 0 or has_move_mount_status != 0:
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'systemd-notify', '--ready']
    add_all_namespaces(conf, cgroupns=True)
    mappings = [
        {
            "containerID": 0,
            # + getuid() makes sure we don't accidently run the container as the user that's running the test.
            "hostID": 8000 + os.getuid(),
            "size": 1,
        },
    ]
    conf['linux']['uidMappings'] = mappings
    conf['linux']['gidMappings'] = mappings
    env = dict(os.environ)
    with tempfile.TemporaryDirectory() as socket_dir:
        env["NOTIFY_SOCKET"] = os.path.join(socket_dir, "notify.socket")
        ready_datagram = None
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.bind(env["NOTIFY_SOCKET"])
            s.settimeout(2)
            def notify_server():
                nonlocal ready_datagram
                ready_datagram = s.recv(1024)

            notify_thread = threading.Thread(target=notify_server)
            notify_thread.start()
            try:
                run_and_get_output(conf, env=env, command='run', chown_rootfs_to=8000)
                notify_thread.join()
                if ready_datagram != b"READY=1":
                    return -1
            except:
                return -1
            finally:
                try:
                    notify_thread.join()
                except:
                    pass
            return 0

def test_empty_home():
    conf = base_config()
    conf['process']['args'] = ['/sbin/init', 'printenv', 'HOME']
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf)
        if "/" not in str(out):
            return -1
    except Exception as e:
        return -1
    return 0

all_tests = {
    "start" : test_start,
    "start-override-config" : test_start_override_config,
    "run-twice" : test_run_twice,
    "sd-notify" : test_sd_notify,
    "sd-notify-file" : test_sd_notify_file,
    "sd-notify-env" : test_sd_notify_env,
    "sd-notify-proxy": test_sd_notify_proxy,
    "test-cwd-relative": test_cwd_relative,
    "test-cwd-relative-subdir": test_cwd_relative_subdir,
    "test-cwd-absolute": test_cwd_absolute,
    "empty-home": test_empty_home,
}

if __name__ == "__main__":
    tests_main(all_tests)
