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
from tests_utils import *


def run_cr_test(conf):
    cid = None
    cr_dir = os.path.join(get_tests_root(), 'checkpoint')
    try:
        _, cid = run_and_get_output(
            conf,
            all_dev_null=True,
            use_popen=True,
            detach=True
        )
        for _ in range(50):
            try:
                s = json.loads(run_crun_command(["state", cid]))
                break
            except Exception as e:
                time.sleep(0.1)

        if s['status'] != "running":
            return -1
        if s['id'] != cid:
            return -1
        with open("/proc/%s/cmdline" % s['pid'], 'r') as cmdline_fd:
            first_cmdline = cmdline_fd.read()

        run_crun_command(["checkpoint", "--image-path=%s" % cr_dir, cid])

        bundle = os.path.join(
            get_tests_root(),
            cid.split('-')[1]
        )

        run_crun_command([
            "restore",
            "-d",
            "--image-path=%s" % cr_dir,
            "--bundle=%s" % bundle,
            cid
        ])

        s = json.loads(run_crun_command(["state", cid]))
        if s['status'] != "running":
            return -1
        if s['id'] != cid:
            return -1
        with open("/proc/%s/cmdline" % s['pid'], 'r') as cmdline_fd:
            second_cmdline = cmdline_fd.read()
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
}

if __name__ == "__main__":
    tests_main(all_tests)
