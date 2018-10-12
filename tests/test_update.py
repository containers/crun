#!/bin/env $PYTHON
# crun - OCI runtime written in C
#
# Copyright (C) 2017, 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
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

import time
import json
import subprocess
import os
import shutil
import sys
from tests_utils import *

def test_update():
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    temp_dir = tempfile.mkdtemp(dir=get_tests_root())
    out, container_id = run_and_get_output(conf, detach=True)
    try:
        p = "/sys/fs/cgroup/memory/system.slice/libcrun-%s.scope/memory.limit_in_bytes" % container_id
        if not os.path.exists(p):
            return 77
        with open(p) as f:
            oldval = f.read()

        res_file = os.path.join(temp_dir, "resources")
        with open(res_file, 'w') as f:
            f.write('{"memory": {"limit": 2000000}}')

        run_crun_command(["update", "-r", res_file, container_id])

        with open(p) as f:
            newval = f.read()

        if newval != oldval:
            return 0
    finally:
        run_crun_command(["delete", "-f", container_id])
        shutil.rmtree(temp_dir)
    return 1


all_tests = {
    "test-update" : test_update,
}

if __name__ == "__main__":
    tests_main(all_tests)
