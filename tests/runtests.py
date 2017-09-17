#!/bin/python -Es
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
import tempfile
import os
import shutil
import sys
import re

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
            "/init"
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

def add_all_namespaces(conf):
    has = {}
    for i in conf['linux']['namespaces']:
        has[i['type']] = i['type']
    for i in ['pid', 'user', 'cgroup', 'ipc', 'uts', 'network']:
        if i not in has:
            conf['linux']['namespaces'].append({"type" : i})

def parse_proc_status(content):
    r = {}
    for i in content.split("\n"):
        if ':\t' not in i:
            continue
        k, v = i.split(':\t', 1)
        r[k] = v.strip()
    return r

def base_config():
    return json.loads(base_conf)

def get_tests_root():
    return '%s/.testsuite-run-%d' % (os.getcwd(), os.getpid())

def run_and_get_output(config):
    cwd = os.getcwd()
    temp_dir = tempfile.mkdtemp(dir=get_tests_root())
    rootfs = os.path.join(temp_dir, "rootfs")
    os.makedirs(rootfs)
    id_container = 'test-%s' % os.path.basename(temp_dir)
    try:
        with open(os.path.join(temp_dir, "config.json"), "w") as config_file:
            conf = json.dumps(config)
            config_file.write(conf)

        shutil.copy2("tests/init", os.path.join(rootfs, "init"))
        crun = os.path.join(cwd, "crun")
        return subprocess.check_output([crun, 'run', id_container], cwd=temp_dir)
    finally:
        shutil.rmtree(temp_dir)

def test_pid():
    if os.getuid() != 0:
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    conf['linux']['namespaces'].append({"type" : "pid"})
    out = run_and_get_output(conf)
    pid = parse_proc_status(out)['Pid']
    if pid == "1":
        return 0
    return -1

def test_pid_user():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    out = run_and_get_output(conf)
    pid = parse_proc_status(out)['Pid']
    if pid == "1":
        return 0
    return -1

def test_no_caps():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    for i in ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']:
        conf['process']['capabilities'][i] = []
    out = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    for i in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        if proc_status[i] != "0000000000000000":
            return -1
    return 0

def test_some_caps():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    for i in ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']:
        conf['process']['capabilities'][i] = []
    out = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    for i in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        if proc_status[i] != "0000000000000000":
            return -1
    return 0

def test_uid():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['uid'] = 1000
    out = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    ids = proc_status['Uid'].split()
    for i in ids:
        if i != "1000":
            return -1
    return 0

def helper_test_some_caps(captypes, proc_name):
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    for i in captypes + ['bounding']:
        conf['process']['capabilities'][i] = ["CAP_SYS_ADMIN"]
    out = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    if proc_status[proc_name] == "0000000000000000":
        return -1
    return 0

def test_some_caps_effective():
    return helper_test_some_caps(["effective"], 'CapEff')

def test_some_caps_bounding():
    return helper_test_some_caps(["bounding"], 'CapBnd')

def test_some_caps_inheritable():
    return helper_test_some_caps(["inheritable"], 'CapInh')

def test_some_caps_ambient():
    return helper_test_some_caps(["ambient", "permitted", "inheritable"], 'CapAmb')

def test_some_caps_permitted():
    return helper_test_some_caps(["permitted"], 'CapPrm')


all_tests = {"pid" : test_pid,
	     "pid-user" : test_pid_user,
             "no-caps" : test_no_caps,
             "uid" : test_uid,
             "some-caps-effective" : test_some_caps_effective,
             "some-caps-bounding" : test_some_caps_bounding,
             "some-caps-inheritable" : test_some_caps_inheritable,
             "some-caps-ambient" : test_some_caps_ambient,
             "some-caps-permitted" : test_some_caps_permitted
}

def run_all_tests():
    print("1..%d" % len(all_tests.keys()))
    cur = 0
    for k, v in all_tests.items():
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
            sys.stderr.write(str(e))
            ret = -1
            print("not ok %d - %s" % (cur, k))

if __name__ == "__main__":
    tests_root = get_tests_root()
    try:
        os.makedirs(tests_root)
        run_all_tests()
    finally:
        shutil.rmtree(tests_root)
