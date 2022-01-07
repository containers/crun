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

def add_all_namespaces(conf, cgroupns=False, userns=False, netns=True):
    has = {}
    for i in conf['linux']['namespaces']:
        has[i['type']] = i['type']
    namespaces = ['pid', 'ipc', 'uts']
    if cgroupns:
        namespaces = namespaces + ["cgroup"]
    if userns:
        namespaces = namespaces + ["user"]
    if netns:
        namespaces = namespaces + ["network"]
    for i in namespaces:
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

def get_tests_root_status():
    return os.path.join(get_tests_root(), "root")

def get_crun_path():
    cwd = os.getcwd()
    return os.getenv("OCI_RUNTIME") or os.path.join(cwd, "crun")

def run_and_get_output(config, detach=False, preserve_fds=None, pid_file=None,
                       command='run', env=None, use_popen=False, hide_stderr=False, cgroup_manager='cgroupfs',
                       all_dev_null=False, id_container=None, relative_config_path="config.json",
                       chown_rootfs_to=None):

    # Some tests require that the container user, which might not be the
    # same user as the person running the tests, is able to resolve the full path
    # to its own tree
    if chown_rootfs_to is not None:
        temp_dir = tempfile.mkdtemp()
    else:
        temp_dir = tempfile.mkdtemp(dir=get_tests_root())

    rootfs = os.path.join(temp_dir, "rootfs")
    os.makedirs(rootfs)
    for i in ["usr/bin", "etc", "var", "lib", "lib64", "usr/share/zoneinfo/Europe", "proc", "sys", "dev"]:
        os.makedirs(os.path.join(rootfs, i))
    with open(os.path.join(rootfs, "var", "file"), "w+") as f:
        f.write("file")

    if id_container is None:
        id_container = 'test-%s' % os.path.basename(temp_dir)

    config_path = os.path.join(temp_dir, relative_config_path)
    config_dir = os.path.dirname(config_path)
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

    with open(config_path, "w") as config_file:
        conf = json.dumps(config)
        config_file.write(conf)

    init = os.getenv("INIT") or "tests/init"
    crun = get_crun_path()

    os.makedirs(os.path.join(rootfs, "sbin"))
    shutil.copy2(init, os.path.join(rootfs, "init"))
    shutil.copy2(init, os.path.join(rootfs, "sbin", "init"))

    open(os.path.join(rootfs, "usr/share/zoneinfo/Europe/Rome"), "w").close()
    os.symlink("../usr/share/zoneinfo/Europe/Rome", os.path.join(rootfs, "etc/localtime"))
    os.symlink("../foo/bar/not/here", os.path.join(rootfs, "etc/not-existing"))

    if chown_rootfs_to is not None:
        os.chown(temp_dir, chown_rootfs_to, chown_rootfs_to)
        for root, dirs, files in os.walk(temp_dir):
            for f in dirs + files:
                os.chown(os.path.join(root, f), chown_rootfs_to, chown_rootfs_to, follow_symlinks=False)

    detach_arg = ['--detach'] if detach else []
    preserve_fds_arg = ['--preserve-fds', str(preserve_fds)] if preserve_fds else []
    pid_file_arg = ['--pid-file', pid_file] if pid_file else []
    relative_config_path = ['--config', relative_config_path] if relative_config_path else []

    root = get_tests_root_status()
    args = [crun, "--cgroup-manager", cgroup_manager, "--root", root, command] + relative_config_path + preserve_fds_arg + detach_arg + pid_file_arg + [id_container]

    stderr = subprocess.STDOUT
    if hide_stderr:
        stderr = None
    stdin = None
    stdout = None
    # For the initial limited checkpoint/restore support everything
    # has to be redirect to /dev/null
    if all_dev_null:
        stdin = subprocess.DEVNULL
        stdout = subprocess.DEVNULL
        stderr = subprocess.DEVNULL
    if use_popen:
        if not stdout:
            stdout=subprocess.PIPE
        return subprocess.Popen(args, cwd=temp_dir, stdout=stdout,
                                stderr=stderr, stdin=stdin, env=env,
                                close_fds=False), id_container
    else:
        return subprocess.check_output(args, cwd=temp_dir, stderr=stderr, env=env, close_fds=False).decode(), id_container

def run_crun_command(args):
    root = get_tests_root_status()
    crun = get_crun_path()
    args = [crun, "--root", root] + args
    return subprocess.check_output(args, close_fds=False).decode()

def running_on_systemd():
    with open('/proc/1/comm') as f:
        return "systemd" in f.readline()

def tests_main(all_tests):
    os.environ["LANG"] = "C"
    tests_root = get_tests_root()
    try:
        os.makedirs(tests_root)
        run_all_tests(all_tests, os.getenv("RUN_TESTS"))
    finally:
        shutil.rmtree(tests_root)

def is_rootless():
    if os.getuid() != 0:
        return True
    with open("/proc/self/uid_map") as f:
        if "4294967295" in f.readline():
            return False
    return True

def get_crun_feature_string():
    for i in run_crun_command(['--version']).split('\n'):
        if i.startswith('+'):
            return i
    return ''
