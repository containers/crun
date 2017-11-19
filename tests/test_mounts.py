#!/bin/env $PYTHON
# crun - OCI runtime written in C
#
# Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
# libocispec is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# libocispec is distributed in the hope that it will be useful,
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
import tempfile

try:
    import libmount
except Exception:
    print("1..0")
    sys.exit(0)

def helper_mount(options):
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    mount_opt = {"destination": "/var/dir", "type": "tmpfs", "source": "tmpfs", "options": [options]}
    conf['mounts'].append(mount_opt)
    out = run_and_get_output(conf)
    with tempfile.NamedTemporaryFile(mode='w', delete=True) as f:
        f.write(out)
        f.flush()
        t = libmount.Table(f.name)
        m = t.find_target('/var/dir')
        return [m.vfs_options, m.fs_options]
    return -1

def test_mount_ro():
    a = helper_mount("ro")[0]
    if "ro" in a:
        return 0
    return -1

def test_mount_rw():
    a = helper_mount("rw")[0]
    if "rw" in a:
        return 0
    return -1

def test_mount_relatime():
    a = helper_mount("relatime")[0]
    if "relatime" in a:
        return 0
    return -1

def test_mount_strictatime():
    a = helper_mount("strictatime")[0]
    if "relatime" not in a:
        return 0
    return -1

def test_mount_exec():
    a = helper_mount("exec")[0]
    if "noexec" not in a:
        return 0
    return -1

def test_mount_noexec():
    a = helper_mount("noexec")[0]
    if "noexec" in a:
        return 0
    return -1

def test_mount_suid():
    a = helper_mount("suid")[0]
    if "nosuid" not in a:
        return 0
    return -1

def test_mount_nosuid():
    a = helper_mount("nosuid")[0]
    if "nosuid" in a:
        return 0
    return -1

def test_mount_sync():
    a = helper_mount("sync")[1]
    if "sync" in a:
        return 0
    return -1

def test_mount_dirsync():
    a = helper_mount("dirsync")[1]
    if "dirsync" in a:
        return 0
    return -1

all_tests = {
    "test-mount-ro" : test_mount_ro,
    "test-mount-rw" : test_mount_rw,
    "test-mount-relatime" : test_mount_relatime,
    "test-mount-strictatime" : test_mount_strictatime,
    "test-mount-exec" : test_mount_exec,
    "test-mount-noexec" : test_mount_noexec,
    "test-mount-suid" : test_mount_suid,
    "test-mount-nosuid" : test_mount_nosuid,
    "test-mount-sync" : test_mount_sync,
    "test-mount-dirsync" : test_mount_dirsync,
}

if __name__ == "__main__":
    tests_main(all_tests)
