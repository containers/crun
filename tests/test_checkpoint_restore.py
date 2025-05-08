#!/bin/env python3
# crun - OCI runtime written in C
#
# Copyright (C) 2020 Adrian Reber <areber@redhat.com>
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
import os
import subprocess
from tests_utils import *

criu_version = 0

def _get_criu_version():
    global criu_version
    if criu_version != 0:
        return criu_version

    args = ["criu", "--version"]
    version_output = subprocess.check_output(args, close_fds=False).decode().split('\n')

    if len(version_output) < 1:
        return 0

    first_line = version_output[0].split(':')

    if len(first_line) != 2:
        return 0

    version_string = first_line[1].split('.')

    if len(version_string) < 2:
        return 0

    version = int(version_string[0]) * 10000
    version += int(version_string[1]) * 100

    if len(version_string) == 3:
        version += int(version_string[2])

    if len(version_output) > 1:
        if version_output[1].startswith('GitID'):
            version -= version % 100
            version += 100

    return version


def _get_cmdline(cid, tests_root):
    s = {}
    for _ in range(50):
        try:
            if os.path.exists(os.path.join(tests_root, 'root/%s/status' % cid)):
                s = json.loads(run_crun_command(["state", cid]))
                break
            else:
                time.sleep(0.1)
        except Exception as e:
            time.sleep(0.1)

    if len(s) == 0:
        return ""

    if s['status'] != "running":
        return ""
    if s['id'] != cid:
        return ""
    with open("/proc/%s/cmdline" % s['pid'], 'r') as cmdline_fd:
        return cmdline_fd.read()
    return ""


def run_cr_test(conf):
    cid = None
    cr_dir = os.path.join(get_tests_root(), 'checkpoint')
    work_dir = 'work-dir'
    try:
        _, cid = run_and_get_output(
            conf,
            all_dev_null=True,
            use_popen=True,
            detach=True
        )

        first_cmdline = _get_cmdline(cid, get_tests_root())
        if first_cmdline == "":
            return -1

        run_crun_command([
            "checkpoint",
            "--image-path=%s" % cr_dir,
            "--work-path=%s" % work_dir,
            cid
        ])

        bundle = os.path.join(
            get_tests_root(),
            cid.split('-')[1]
        )

        run_crun_command([
            "restore",
            "-d",
            "--image-path=%s" % cr_dir,
            "--work-path=%s" % work_dir,
            "--bundle=%s" % bundle,
            cid
        ])

        second_cmdline = _get_cmdline(cid, get_tests_root())
        if first_cmdline != second_cmdline:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0


def test_cr_pre_dump():
    if is_rootless() or 'CRIU' not in get_crun_feature_string():
        return 77

    if _get_criu_version() < 31700:
        return 77

    has_pre_dump = False
    for i in run_crun_command(["checkpoint", "--help"]).split('\n'):
        if "pre-dump" in i:
            has_pre_dump = True
            break

    if not has_pre_dump:
        return 77

    def _get_pre_dump_size(cr_dir):
        size = 0
        for f in os.listdir(cr_dir):
            if os.path.isfile(os.path.join(cr_dir, f)):
                size += os.path.getsize(os.path.join(cr_dir, f))
        return size

    conf = base_config()
    conf['process']['args'] = [
            '/init',
            'memhog',
            '10'
    ]
    add_all_namespaces(conf)

    cid = None
    cr_dir = os.path.join(get_tests_root(), 'pre-dump')
    try:
        _, cid = run_and_get_output(
            conf,
            all_dev_null=True,
            use_popen=True,
            detach=True
        )

        first_cmdline = _get_cmdline(cid, get_tests_root())
        if first_cmdline == "":
            return -1

        # Let's do one pre-dump first
        run_crun_command([
            "checkpoint",
            "--pre-dump",
            "--image-path=%s" % cr_dir,
            "--work-path=%s" % work_dir,
            cid
        ])

        # Get the size of the pre-dump
        pre_dump_size = _get_pre_dump_size(cr_dir)

        # Do the final dump. This dump should be much smaller.
        cr_dir = os.path.join(get_tests_root(), 'checkpoint')
        work_dir = 'work-dir'
        run_crun_command([
            "checkpoint",
            "--parent-path=../pre-dump",
            "--image-path=%s" % cr_dir,
            "--work-path=%s" % work_dir,
            cid
        ])

        final_dump_size = _get_pre_dump_size(cr_dir)
        if (final_dump_size > pre_dump_size):
            # If the final dump is not smaller than the pre-dump
            # something was not working as expected.
            return -1

        bundle = os.path.join(
            get_tests_root(),
            cid.split('-')[1]
        )

        run_crun_command([
            "restore",
            "-d",
            "--image-path=%s" % cr_dir,
            "--bundle=%s" % bundle,
            "--work-path=%s" % work_dir,
            cid
        ])

        second_cmdline = _get_cmdline(cid, get_tests_root())
        if first_cmdline != second_cmdline:
            return -1

    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0


def test_cr():
    if is_rootless() or 'CRIU' not in get_crun_feature_string():
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    return run_cr_test(conf)


def test_cr_with_ext_ns():
    if is_rootless() or 'CRIU' not in get_crun_feature_string():
        return 77

    if _get_criu_version() < 31601:
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    ns_path = os.path.join('/proc', str(os.getpid()), 'ns')
    for ns in conf['linux']['namespaces']:
        if ns['type'] == 'pid':
            ns.update({'path': os.path.join(ns_path, 'pid')})
        if ns['type'] == 'network':
            ns.update({'path': os.path.join(ns_path, 'net')})
        if ns['type'] == 'ipc':
            ns.update({'path': os.path.join(ns_path, 'ipc')})
        if ns['type'] == 'uts':
            ns.update({'path': os.path.join(ns_path, 'uts')})
        if ns['type'] == 'time':
            ns.update({'path': os.path.join(ns_path, 'time')})

    return run_cr_test(conf)


all_tests = {
    "checkpoint-restore": test_cr,
    "checkpoint-restore-ext-ns": test_cr_with_ext_ns,
    "checkpoint-restore-pre-dump": test_cr_pre_dump,
}

if __name__ == "__main__":
    tests_main(all_tests)
