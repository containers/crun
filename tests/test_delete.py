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
import subprocess
import os
from tests_utils import *

def test_simple_delete():
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    out, container_id = run_and_get_output(conf, detach=True, hide_stderr=True)
    if out != "":
        return -1
    try:
        state = json.loads(run_crun_command(["state", container_id]))
        if state['status'] != "running":
            return -1
        if state['id'] != container_id:
            return -1
    finally:
        freezerCreated=False
        if not os.path.exists("/sys/fs/cgroup/cgroup.controllers") and os.access('/sys/fs/cgroup/freezer/', os.W_OK):
            # cgroupv1 freezer can easily simulate stuck or breaking `crun delete -f <cid>`
            # this should be only done on cgroupv1 systems
            if not os.path.exists("/sys/fs/cgroup/freezer/frozen/"):
                freezerCreated=True
                os.makedirs("/sys/fs/cgroup/freezer/frozen/")
            with open('/sys/fs/cgroup/freezer/frozen/tasks', 'w') as f:
                f.write(str(state['pid']))
            with open('/sys/fs/cgroup/freezer/frozen/freezer.state', 'w') as f:
                f.write('FROZEN')
        run_crun_command(["delete", "-f", container_id])
        if freezerCreated:
            os.rmdir("/sys/fs/cgroup/freezer/frozen/")
    return 0

all_tests = {
    "test_simple_delete" : test_simple_delete,
}

if __name__ == "__main__":
    tests_main(all_tests)

