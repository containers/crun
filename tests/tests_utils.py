#!/bin/env $PYTHON
# crun - OCI runtime written in C
#
# Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
# crun is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
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
import shutil
import sys
import os
import tempfile
import subprocess

base_conf = """
{
    "ociVersion": "1.0.0",
    "process": {
	"user": {
	    "uid": 0,
	    "gid": 0
	},
        "terminal": false,
	"args": [
            "/init",
            "true"
	],
	"env": [
	    "PATH=/bin",
	    "TERM=xterm"
	],
	"cwd": "/",
	"noNewPrivileges": true
    },
    "root": {
	"path": "rootfs",
	"readonly": true
    },
    "mounts": [
	{
	    "destination": "/proc",
	    "type": "proc"
	},
	{
	    "destination": "/sys",
	    "type": "sysfs",
	    "source": "sysfs",
	    "options": [
		"nosuid",
		"noexec",
		"nodev",
		"ro"
	    ]
	},
	{
	    "destination": "/sys/fs/cgroup",
	    "type": "cgroup",
	    "source": "cgroup",
	    "options": [
		"nosuid",
		"noexec",
		"nodev",
		"relatime",
		"rw"
	    ]
	},
	{
	    "destination": "/dev",
	    "type": "tmpfs",
	    "source": "tmpfs",
	    "options": [
		"nosuid",
		"strictatime",
		"mode=755",
		"size=65536k"
	    ]
	},
	{
	    "destination": "/dev/pts",
	    "type": "devpts",
	    "source": "devpts",
	    "options": [
		"nosuid",
		"noexec",
		"newinstance",
		"ptmxmode=0666",
		"mode=0620"
	    ]
	},
	{
	    "destination": "/dev/shm",
	    "type": "tmpfs",
	    "source": "shm",
	    "options": [
		"nosuid",
		"noexec",
		"nodev",
		"mode=1777",
		"size=65536k"
	    ]
	},
	{
	    "destination": "/dev/mqueue",
	    "type": "mqueue",
	    "source": "mqueue",
	    "options": [
		"nosuid",
		"noexec",
		"nodev"
	    ]
	}
    ],
    "linux": {
	"rootfsPropagation": "rprivate",
	"namespaces": [
	    {
		"type": "mount"
	    }
	]
    }
}
"""

def base_config():
    return json.loads(base_conf)

def parse_proc_status(content):
    r = {}
    for i in content.split("\n"):
        if ':\t' not in i:
            continue
        k, v = i.split(':\t', 1)
        r[k] = v.strip()
    return r

def add_all_namespaces(conf):
    has = {}
    for i in conf['linux']['namespaces']:
        has[i['type']] = i['type']
    for i in ['pid', 'user', 'cgroup', 'ipc', 'uts', 'network']:
        if i not in has:
            conf['linux']['namespaces'].append({"type" : i})

def run_all_tests(all_tests, allowed_tests):
    tests = all_tests
    if allowed_tests is not None:
        allowed_tests = allowed_tests.split()
        tests = {k: v for k, v in tests.items() if k in allowed_tests}

    print("1..%d" % len(tests))
    cur = 0
    for k, v in tests.items():
        cur = cur + 1
        ret = -1
        try:
            ret = v()
            if ret == 0:
                print("ok %d - %s" % (cur, k))
            elif ret == 77:
                print("ok %d - %s #SKIP" % (cur, k))
            else:
                print("not ok %d - %s" % (cur, k))
        except Exception as e:
            if hasattr(e, 'output'):
                sys.stderr.write(str(e.output) + "\n")
            sys.stderr.write(str(e) + "\n")
            ret = -1
            print("not ok %d - %s" % (cur, k))

def get_tests_root():
    return '%s/.testsuite-run-%d' % (os.getcwd(), os.getpid())

def run_and_get_output(config, detach=False, preserve_fds=None, pid_file=None):
    cwd = os.getcwd()
    temp_dir = tempfile.mkdtemp(dir=get_tests_root())
    rootfs = os.path.join(temp_dir, "rootfs")
    os.makedirs(rootfs)
    for i in ["usr/bin", "etc", "var", "lib", "lib64"]:
        os.makedirs(os.path.join(rootfs, i))
    with open(os.path.join(rootfs, "var", "file"), "w+") as f:
        f.write("file")
    id_container = 'test-%s' % os.path.basename(temp_dir)
    try:
        with open(os.path.join(temp_dir, "config.json"), "w") as config_file:
            conf = json.dumps(config)
            config_file.write(conf)

        shutil.copy2("tests/init", os.path.join(rootfs, "init"))
        crun = os.path.join(cwd, "crun")
        detach_arg = ['--detach'] if detach else []
        preserve_fds_arg = ['--preserve-fds', str(preserve_fds)] if preserve_fds else []
        pid_file_arg = ['--pid-file', pid_file] if pid_file else []
        
        args = [crun, 'run'] + preserve_fds_arg + detach_arg + pid_file_arg + [id_container]
        return subprocess.check_output(args, cwd=temp_dir, stderr=subprocess.STDOUT, close_fds=False).decode()
    finally:
        shutil.rmtree(temp_dir)

def tests_main(all_tests):
    os.environ["LANG"] = "C"
    tests_root = get_tests_root()
    try:
        os.makedirs(tests_root)
        run_all_tests(all_tests, os.getenv("RUN_TESTS"))
    finally:
        shutil.rmtree(tests_root)
