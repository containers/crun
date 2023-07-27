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

import subprocess
import sys
import time
from tests_utils import *


def is_cgroup_v2_unified():
    return subprocess.check_output("stat -c%T -f /sys/fs/cgroup".split()).decode("utf-8").strip() == "cgroup2fs"

def test_resources_fail_with_enoent():
    if is_rootless():
        return 77
    if not is_cgroup_v2_unified():
        return 77

    conf = base_config()
    add_all_namespaces(conf)
    conf['linux']['resources'] = {"unified" : {"memory.DOESNTEXIST" : "baz"}}
    conf['process']['args'] = ['/init', 'echo', 'hi']

    proc, _ = run_and_get_output(conf, use_popen=True)
    out, _ = proc.communicate()

    if "no such file or directory" in out.decode().lower():
        return 0

    return -1

def test_resources_pid_limit():
    if is_rootless():
        return 77
    conf = base_config()
    conf['linux']['resources'] = {"pids" : {"limit" : 1024}}
    add_all_namespaces(conf)

    fn = "/sys/fs/cgroup/pids/pids.max"
    if is_cgroup_v2_unified():
        fn = "/sys/fs/cgroup/pids.max"
        conf['linux']['namespaces'].append({"type" : "cgroup"})

    conf['process']['args'] = ['/init', 'cat', fn]

    out, _ = run_and_get_output(conf)
    if "1024" not in out:
        sys.stderr.write("found %s instead of 1024\n" % out)
        return -1
    return 0

def test_resources_pid_limit_userns():
    if is_rootless():
        return 77

    conf = base_config()
    conf['linux']['resources'] = {"pids" : {"limit" : 1024}}
    add_all_namespaces(conf)

    mappings = [
        {
            "containerID": 0,
            "hostID": 1,
            "size": 1,
        },
        {
            "containerID": 1,
            "hostID": 0,
            "size": 1,
        }
    ]

    conf['linux']['namespaces'].append({"type" : "user"})
    conf['linux']['uidMappings'] = mappings
    conf['linux']['gidMappings'] = mappings

    fn = "/sys/fs/cgroup/pids/pids.max"
    if is_cgroup_v2_unified():
        fn = "/sys/fs/cgroup/pids.max"
        conf['linux']['namespaces'].append({"type" : "cgroup"})

    conf['process']['args'] = ['/init', 'cat', fn]

    out, _ = run_and_get_output(conf)
    if "1024" not in out:
        sys.stderr.write("found %s instead of 1024\n" % out)
        return -1
    return 0

def test_resources_unified_invalid_controller():
    if not is_cgroup_v2_unified() or is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {}
    conf['linux']['resources']['unified'] = {
            "foo.bar": "doesntmatter"
    }
    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run', detach=True)
        # must raise an exception, fail if it doesn't.
        return -1
    except Exception as e:
        if 'the requested cgroup controller `foo` is not available' in e.stdout.decode("utf-8").strip():
            return 0
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_resources_unified_invalid_key():
    if not is_cgroup_v2_unified() or is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {}
    conf['linux']['resources']['unified'] = {
            "NOT-A-VALID-KEY": "doesntmatter"
    }
    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run', detach=True)
        # must raise an exception, fail if it doesn't.
        return -1
    except Exception as e:
        if 'the specified key has not the form CONTROLLER.VALUE `NOT-A-VALID-KEY`' in e.stdout.decode("utf-8").strip():
            return 0
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_resources_unified():
    if not is_cgroup_v2_unified() or is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {}
    conf['linux']['resources']['unified'] = {
            "memory.high": "1073741824"
    }
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
        out = run_crun_command(["exec", cid, "/init", "cat", "/sys/fs/cgroup/memory.high"])
        if "1073741824" not in out:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_resources_cpu_weight():
    if not is_cgroup_v2_unified() or is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {}
    conf['linux']['resources']['unified'] = {
            "cpu.weight": "1234"
    }
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
        out = run_crun_command(["exec", cid, "/init", "cat", "/sys/fs/cgroup/cpu.weight"])
        if "1234" not in out:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_resources_cgroupv2_swap_0():
    if not is_cgroup_v2_unified() or is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {}
    conf['linux']['resources']['memory'] = {
            "swap": 0
    }
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
        out = run_crun_command(["exec", cid, "/init", "cat", "/sys/fs/cgroup/memory.swap.max"])
        if "0" not in out:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_resources_cpu_quota_minus_one():
    if is_cgroup_v2_unified() or is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpu/cpu.cfs_quota_us']

    conf['linux']['resources'] = {}
    conf['linux']['resources']['cpu'] = {
            "quota": -1
    }
    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if "-1" not in out:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0



def test_resources_cpu_weight_systemd():
    if not is_cgroup_v2_unified() or is_rootless():
        return 77
    if 'SYSTEMD' not in get_crun_feature_string():
        return 77
    if not running_on_systemd():
        return 77

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {}
    conf['linux']['resources']['unified'] = {

            "cpu.weight": "1234"
    }
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True, cgroup_manager="systemd")
        out = run_crun_command(["exec", cid, "/init", "cat", "/sys/fs/cgroup/cpu.weight"])
        if "1234" not in out:
            sys.stderr.write("found wrong CPUWeight for the container cgroup\n")
            return -1

        state = run_crun_command(['state', cid])
        scope = json.loads(state)['systemd-scope']

        out = subprocess.check_output(['systemctl', 'show','-PCPUWeight', scope ], close_fds=False).decode().strip()
        # try once more against the user manager, as if one exists, crun will prefer it; see bug #1197
        if out != "1234":
            out = subprocess.check_output(['systemctl', '--user', 'show','-PCPUWeight', scope ], close_fds=False).decode().strip()

        if out != "1234":
            sys.stderr.write("found wrong CPUWeight for the systemd scope\n")
            return 1

        run_crun_command(['update', '--cpu-share', '4321', cid])
        # this is the expected cpu weight after the conversion from the CPUShares
        expected_weight = "165"

        out = run_crun_command(["exec", cid, "/init", "cat", "/sys/fs/cgroup/cpu.weight"])
        if expected_weight not in out:
            sys.stderr.write("found wrong CPUWeight %s for the container cgroup\n" % out)
            return -1

        out = subprocess.check_output(['systemctl', 'show','-PCPUWeight', scope ], close_fds=False).decode().strip()
        # as above
        if out != expected_weight:
            out = subprocess.check_output(['systemctl', '--user', 'show','-PCPUWeight', scope ], close_fds=False).decode().strip()

        if out != expected_weight:
            sys.stderr.write("found wrong CPUWeight for the systemd scope\n")
            return 1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0


def test_resources_exec_cgroup():
    if not is_cgroup_v2_unified() or is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'create-sub-cgroup-and-wait', 'foo']
    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run', detach=True)
        # Give some time to pid 1 to move to the new cgroup
        time.sleep(2)
        out = run_crun_command(["exec", "--cgroup=/foo", cid, "/init", "cat", "/proc/self/cgroup"])
        for i in out.split("\n"):
            if i == "":
                continue
            if "/foo" not in i:
                sys.stderr.write("/foo not found in the output")
                return -1
        return 0
    except Exception as e:
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0


all_tests = {
    "resources-v2-swap-disabled": test_resources_cgroupv2_swap_0,
    "resources-pid-limit" : test_resources_pid_limit,
    "resources-pid-limit-userns" : test_resources_pid_limit_userns,
    "resources-unified" : test_resources_unified,
    "resources-unified-invalid-controller" : test_resources_unified_invalid_controller,
    "resources-unified-invalid-key" : test_resources_unified_invalid_key,
    "resources-unified-exec-cgroup" : test_resources_exec_cgroup,
    "resources-fail-with-enoent" : test_resources_fail_with_enoent,
    "resources-cpu-weight" : test_resources_cpu_weight,
    "resources-cpu-weight-systemd" : test_resources_cpu_weight_systemd,
    "resources-cpu-quota-minus-one" : test_resources_cpu_quota_minus_one,
}

if __name__ == "__main__":
    tests_main(all_tests)
