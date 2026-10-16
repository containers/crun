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
import resource
import subprocess
import os
import time
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
                # also ignore profiling messages from coverage builds
                if not output or b'Device or resource busy' in output or b'profiling:' in output:
                    # if output is empty or expected error or profiling output, pass
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

def test_delete_exited_main_thread():
    """Delete a container sharing the host PID namespace with a process whose main thread exited"""
    if is_rootless():
        return (77, "requires root privileges")

    conf = base_config()
    conf['process']['args'] = ['/init', 'fork-and-exit-main-thread']
    add_all_namespaces(conf, pidns=False)

    def task_state(pid, tid):
        with open("/proc/%d/task/%d/stat" % (pid, tid)) as f:
            return f.read().rsplit(")", 1)[1].split()[0]

    def is_alive(pid):
        try:
            for tid in os.listdir("/proc/%d/task" % pid):
                if task_state(pid, int(tid)) not in ("Z", "X"):
                    return True
        except FileNotFoundError:
            pass
        return False

    _, container_id = run_and_get_output(conf, detach=True, hide_stderr=True)

    child = None
    try:
        state = json.loads(run_crun_command(["state", container_id]))
        children_path = "/proc/%d/task/%d/children" % (state['pid'], state['pid'])
        for _ in range(100):
            with open(children_path) as f:
                children = f.read().split()
            if children:
                child = int(children[0])
                if task_state(child, child) == "Z" and is_alive(child):
                    break
            time.sleep(0.1)
        else:
            logger.info("the process with the exited main thread was not found")
            return -1

        try:
            run_crun_command_raw(["delete", "-f", container_id])
        except subprocess.CalledProcessError as exc:
            logger.info("delete failed: %s", exc.output)
            return -1

        for _ in range(50):
            if not is_alive(child):
                return 0
            time.sleep(0.1)
        logger.info("process %d is still alive after the delete", child)
        return -1
    finally:
        if child is not None and is_alive(child):
            os.kill(child, 9)
        try:
            run_crun_command_raw(["delete", "-f", container_id])
        except subprocess.CalledProcessError:
            pass
def test_delete_nested_directories():
    """Delete a state directory nested deeper than the number of files that can be open"""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    out, container_id = run_and_get_output(conf, detach=True, hide_stderr=True)
    if out != "":
        return -1

    state_dir = os.path.join(get_tests_root_status(), container_id)
    os.makedirs(os.path.join(state_dir, *(["d"] * 256)))

    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, limits[1]))
    try:
        run_crun_command_raw(["delete", "-f", container_id])
    except subprocess.CalledProcessError as exc:
        logger.error("Status : FAIL %s %s", exc.returncode, exc.output)
        return -1
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, limits)

    if os.path.exists(state_dir):
        return -1

    return 0

def test_help_delete():
    out = run_crun_command(["delete", "--help"])
    if "Usage: crun [OPTION...] delete CONTAINER" not in out:
        return -1
    
    return 0

all_tests = {
    "test_simple_delete" : test_simple_delete,
    "test_multiple_containers_delete" : test_multiple_containers_delete,
    "test_delete_exited_main_thread": test_delete_exited_main_thread,
    "test_delete_nested_directories" : test_delete_nested_directories,
    "test_help_delete": test_help_delete,
}

if __name__ == "__main__":
    tests_main(all_tests)

