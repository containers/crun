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

    state = None
    freezerCreated = False
    cleanup_result = 0

    try:
        state = json.loads(run_crun_command(["state", container_id]))
        if state['status'] != "running":
            return -1
        if state['id'] != container_id:
            return -1
    finally:
        if state is not None:
            if not os.path.exists("/sys/fs/cgroup/cgroup.controllers") and os.access('/sys/fs/cgroup/freezer/', os.W_OK):
                # cgroupv1 freezer can easily simulate stuck or breaking `crun delete -f <cid>`
                # this should be only done on cgroupv1 systems
                if not os.path.exists("/sys/fs/cgroup/freezer/frozen/"):
                    freezerCreated = True
                    os.makedirs("/sys/fs/cgroup/freezer/frozen/")
                with open('/sys/fs/cgroup/freezer/frozen/tasks', 'w') as f:
                    f.write(str(state['pid']))
                with open('/sys/fs/cgroup/freezer/frozen/freezer.state', 'w') as f:
                    f.write('FROZEN')
            try:
                output = run_crun_command_raw(["delete", "-f", container_id])
            except subprocess.CalledProcessError as exc:
                logger.error("Status : FAIL %s %s", exc.returncode, exc.output)
                cleanup_result = -1
            else:
                # this is expected for cgroup v1 so ignore
                if not output or b'Device or resource busy' in output:
                    # if output is empty or expected error pass
                    pass
                else:
                    # anything else is error
                    logger.error(output)
                    cleanup_result = -1

            if freezerCreated:
                os.rmdir("/sys/fs/cgroup/freezer/frozen/")

    return cleanup_result

def test_multiple_containers_delete():
    """Delete multiple containers with a regular expression"""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    out_test1, container_id_test1 = run_and_get_output(conf, detach=True, hide_stderr=True)
    if out_test1 != "":
        return -1
    out_test2, container_id_test2 = run_and_get_output(conf, detach=True, hide_stderr=True)
    if out_test2 != "":
        return -1

    cleanup_result = 0

    try:
        state_test1 = json.loads(run_crun_command(["state", container_id_test1]))
        if state_test1['status'] != "running":
            return -1
        if state_test1['id'] != container_id_test1:
            return -1
        state_test2 = json.loads(run_crun_command(["state", container_id_test2]))
        if state_test2['status'] != "running":
            return -1
        if state_test2['id'] != container_id_test2:
            return -1
    finally:
        try:
            output = run_crun_command_raw(["delete", "-f", "--regex", "test-*"])
        except subprocess.CalledProcessError as exc:
            logger.error("Status : FAIL %s %s", exc.returncode, exc.output)
            cleanup_result = -1

    return cleanup_result

def test_help_delete():
    out = run_crun_command(["delete", "--help"])
    if "Usage: crun [OPTION...] delete CONTAINER" not in out:
        return -1
    
    return 0

all_tests = {
    "test_simple_delete" : test_simple_delete,
    "test_multiple_containers_delete" : test_multiple_containers_delete,
    "test_help_delete": test_help_delete,
}

if __name__ == "__main__":
    tests_main(all_tests)

