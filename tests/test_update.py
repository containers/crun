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

import os
import shutil
import tempfile
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
            return (77, "cgroup v1 memory controller not available")
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

def test_update_help():
    out = run_crun_command(["update", "--help"])
    if "Usage: crun [OPTION...] update [OPTION]... CONTAINER" not in out:
        return -1
    
    return 0

all_tests = {
    "test-update" : test_update,
    "test-update-help": test_update_help,
}

if __name__ == "__main__":
    tests_main(all_tests)
