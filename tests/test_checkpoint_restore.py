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
import subprocess
import os
import shutil
import sys
from tests_utils import *

def test_cr1():
    if is_rootless():
        return 77
    if 'CRIU' not in get_crun_feature_string():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf, userns=True)
    # User namespace support not working yet for checkpoint/restore
    conf['linux']['namespaces'].remove({'type':'user'})
    cid = None
    cr_dir = os.path.join(get_tests_root(), 'checkpoint')
    try:
        proc, cid = run_and_get_output(conf, all_dev_null=True, use_popen=True, detach=True)
        for i in range(50):
            try:
                s = json.loads(run_crun_command(["state", cid]))
                break
            except Exception as e:
                time.sleep(0.1)


        if s['status'] != "running":
            return -1
        if s['id'] != cid:
            return -1
        cmdline_fd = open("/proc/%s/cmdline" % s['pid'], 'r')
        first_cmdline = cmdline_fd.read()
        cmdline_fd.close()

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
        cmdline_fd = open("/proc/%s/cmdline" % s['pid'], 'r')
        second_cmdline = cmdline_fd.read()
        cmdline_fd.close()
        if first_cmdline != second_cmdline:
            return -1

    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

all_tests = {
    "checkpoint-restore" : test_cr1,
}

if __name__ == "__main__":
    tests_main(all_tests)
