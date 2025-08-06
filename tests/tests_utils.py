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
import traceback
import time

default_umask = 0o22

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

def add_all_namespaces(conf, cgroupns=False, userns=False, netns=True, ipcns=True, utsns=True, pidns=True,time=False):
    has = {}
    for i in conf['linux']['namespaces']:
        has[i['type']] = i['type']
    namespaces = []
    if pidns:
        namespaces = namespaces + ['pid']
    if utsns:
        namespaces = namespaces + ['uts']
    if cgroupns:
        namespaces = namespaces + ["cgroup"]
    if ipcns:
        namespaces = namespaces + ["ipc"]
    if userns:
        namespaces = namespaces + ["user"]
    if netns:
        namespaces = namespaces + ["network"]
    if time:
        namespaces = namespaces + ["time"]
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
        test_start_time = time.time()
        try:
            # recreate the tests_root() directory for each test
            shutil.rmtree(get_tests_root())
            os.mkdir(get_tests_root())

            ret = v()
            test_duration = time.time() - test_start_time
            if ret == 0:
                print("ok %d - %s # %.3fs" % (cur, k, test_duration))
            elif ret == 77:
                print("ok %d - %s #SKIP # %.3fs" % (cur, k, test_duration))
            else:
                print("not ok %d - %s # %.3fs" % (cur, k, test_duration))
                sys.stderr.write("# Test '%s' failed with return code %d\n" % (k, ret))
        except Exception as e:
            test_duration = time.time() - test_start_time
            sys.stderr.write("# Test '%s' failed with exception after %.3fs:\n" % (k, test_duration))
            if hasattr(e, 'output'):
                sys.stderr.write("# Container output: %s\n" % str(e.output))
            sys.stderr.write("# Exception: %s\n" % str(e))
            sys.stderr.write("# Traceback:\n")
            for line in traceback.format_exc().splitlines():
                sys.stderr.write("# %s\n" % line)
            ret = -1
            print("not ok %d - %s # %.3fs" % (cur, k, test_duration))

def get_tests_root():
    return '%s/.testsuite-run-%d' % (os.getcwd(), os.getpid())

def get_tests_root_status():
    return os.path.join(get_tests_root(), "root")

def get_init_path():
    return os.path.abspath(os.getenv("INIT") or "tests/init")

def get_crun_path():
    cwd = os.getcwd()
    return os.getenv("OCI_RUNTIME") or os.path.join(cwd, "crun")

def run_and_get_output(config, detach=False, preserve_fds=None, pid_file=None,
                       keep=False,
                       command='run', env=None, use_popen=False, hide_stderr=False, cgroup_manager='cgroupfs',
                       all_dev_null=False, stdin_dev_null=False, id_container=None, relative_config_path="config.json",
                       chown_rootfs_to=None, callback_prepare_rootfs=None, debug_on_error=None):

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

    init = get_init_path()
    crun = get_crun_path()

    os.makedirs(os.path.join(rootfs, "sbin"))
    shutil.copy2(init, os.path.join(rootfs, "init"))
    shutil.copy2(init, os.path.join(rootfs, "sbin", "init"))

    open(os.path.join(rootfs, "usr/share/zoneinfo/Europe/Rome"), "w").close()
    os.symlink("../usr/share/zoneinfo/Europe/Rome", os.path.join(rootfs, "etc/localtime"))
    os.symlink("../foo/bar/not/here", os.path.join(rootfs, "etc/not-existing"))

    # Populate /etc/passwd inside container rootfs with users root and test for various test-cases.
    passwd = open(os.path.join(rootfs, "usr/share/passwd"), "w")
    passwd.writelines(["root:x:0:0:root:/root:/bin/bash", "\ntest:x:1000:1000:test:/var/empty:/bin/bash"])
    passwd.close()
    os.symlink("../usr/share/passwd", os.path.join(rootfs, "etc/passwd"))

    if chown_rootfs_to is not None:
        os.chown(temp_dir, chown_rootfs_to, chown_rootfs_to)
        for root, dirs, files in os.walk(temp_dir):
            for f in dirs + files:
                os.chown(os.path.join(root, f), chown_rootfs_to, chown_rootfs_to, follow_symlinks=False)

    if callback_prepare_rootfs is not None:
        callback_prepare_rootfs(rootfs)

    detach_arg = ['--detach'] if detach else []
    keep_arg = ['--keep'] if keep else []
    preserve_fds_arg = ['--preserve-fds', str(preserve_fds)] if preserve_fds else []
    pid_file_arg = ['--pid-file', pid_file] if pid_file else []
    relative_config_path = ['--config', relative_config_path] if relative_config_path else []

    root = get_tests_root_status()
    args = [crun, "--cgroup-manager", cgroup_manager, "--root", root, command] + relative_config_path + preserve_fds_arg + detach_arg + keep_arg + pid_file_arg + [id_container]

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
    elif stdin_dev_null:
        stdin = subprocess.DEVNULL

    if use_popen:
        if not stdout:
            stdout=subprocess.PIPE
        return subprocess.Popen(args, cwd=temp_dir,
                                umask=default_umask,
                                stdout=stdout,
                                stderr=stderr, stdin=stdin, env=env,
                                close_fds=False), id_container
    else:
        try:
            return subprocess.check_output(args, cwd=temp_dir, stdin=stdin, stderr=stderr, env=env, close_fds=False, umask=default_umask).decode(), id_container
        except subprocess.CalledProcessError as e:
            sys.stderr.write("# Command failed: %s\n" % ' '.join(args))
            sys.stderr.write("# Working directory: %s\n" % temp_dir)
            sys.stderr.write("# Container ID: %s\n" % id_container)
            sys.stderr.write("# Return code: %d\n" % e.returncode)
            if e.output:
                sys.stderr.write("# Output: %s\n" % e.output.decode('utf-8', errors='ignore'))
            sys.stderr.write("# Config file saved at: %s\n" % config_path)
            if not keep:
                sys.stderr.write("# Note: temporary directory will be cleaned up\n")
            raise

def run_crun_command(args):
    root = get_tests_root_status()
    crun = get_crun_path()
    cmd_args = [crun, "--root", root] + args
    try:
        return subprocess.check_output(cmd_args, close_fds=False).decode()
    except subprocess.CalledProcessError as e:
        sys.stderr.write("# crun command failed: %s\n" % ' '.join(cmd_args))
        sys.stderr.write("# Return code: %d\n" % e.returncode)
        if e.output:
            sys.stderr.write("# Output: %s\n" % e.output.decode('utf-8', errors='ignore'))
        raise

# Similar as run_crun_command but does not performs decode of output and relays error message for further matching
def run_crun_command_raw(args):
    root = get_tests_root_status()
    crun = get_crun_path()
    cmd_args = [crun, "--root", root] + args
    try:
        return subprocess.check_output(cmd_args, close_fds=False, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        sys.stderr.write("# crun command failed: %s\n" % ' '.join(cmd_args))
        sys.stderr.write("# Return code: %d\n" % e.returncode)
        raise

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

def is_cgroup_v2_unified():
    return subprocess.check_output("stat -c%T -f /sys/fs/cgroup".split()).decode("utf-8").strip() == "cgroup2fs"

def get_crun_feature_string():
    for i in run_crun_command(['--version']).split('\n'):
        if i.startswith('+'):
            return i
    return ''
