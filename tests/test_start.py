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
import shutil
import sys
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

all_tests = {
    "start" : test_start,
    "run-twice" : test_run_twice,
    "sd-notify" : test_sd_notify,
    "sd-notify-file" : test_sd_notify_file,
    "sd-notify-env" : test_sd_notify_env,
    "test-cwd-relative": test_cwd_relative,
    "test-cwd-relative-subdir": test_cwd_relative_subdir,
    "test-cwd-absolute": test_cwd_absolute,
}

if __name__ == "__main__":
    tests_main(all_tests)
