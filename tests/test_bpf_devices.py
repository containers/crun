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
import json
import os
from tests_utils import *

def has_bpf_fs():
    """Check if BPF filesystem is mounted"""
    try:
        return os.path.exists("/sys/fs/bpf") and os.path.ismount("/sys/fs/bpf")
    except:
        return False

def get_systemd_version():
    """Get systemd version number"""
    try:
        output = subprocess.check_output(["systemctl", "--version"], universal_newlines=True)
        # First line format: "systemd 250 (250.3-2-arch)"
        first_line = output.split('\n')[0]
        version_str = first_line.split()[1]
        return int(version_str)
    except:
        return 0

def systemd_supports_bpf_program():
    """Check if systemd version supports BPFProgram property (>= 249)"""
    return get_systemd_version() >= 249

def check_bpf_prerequisites():
    """Check all prerequisites for BPF device tests. Returns 77 (skip) if not met, 0 if OK"""
    # Skip if not root
    if is_rootless():
        return (77, "requires root privileges")

    # Skip if not cgroup v2
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    # Skip if systemd not available
    if 'SYSTEMD' not in get_crun_feature_string():
        return (77, "systemd support not compiled in")

    # Skip if not running on systemd
    if not running_on_systemd():
        return (77, "not running on systemd")

    # Skip if no BPF support
    if not has_bpf_fs():
        return (77, "BPF filesystem not available")

    # Skip if systemd doesn't support BPFProgram
    if not systemd_supports_bpf_program():
        return (77, "systemd BPFProgram not supported")

    return 0

def test_bpf_devices_systemd():
    """Test BPF device handling with systemd: property set, file created, and cleanup"""
    ret = check_bpf_prerequisites()
    if ret != 0:
        return ret

    conf = base_config()
    conf['linux']['resources'] = {}
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    bpf_path = None
    try:
        # Run container with systemd cgroup manager.
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True, cgroup_manager="systemd")

        # Get systemd scope.
        state = run_crun_command(['state', cid])
        scope = json.loads(state)['systemd-scope']

        # Test 1: Check that BPFProgram property is set on the scope.

        output = subprocess.check_output(['systemctl', 'show', '-PBPFProgram', scope], close_fds=False).decode().strip()
        if output == "":
            logger.info("BPFProgram property not found or empty")
            return -1

        # Should look like "device:/sys/fs/bpf/crun/crun-xxx_scope".
        if "device:/sys/fs/bpf/crun/" not in output:
            logger.info("Bad BPFProgram property value: `%s`", prop_value)
            return -1

        # Test 2: Check that BPF program file was created.

        # Extract the path.
        bpf_path = output.split("device:", 1)[1]
        if not os.path.exists(bpf_path):
            logger.info("BPF program file `%s` not found", prog_file)
            return -1

        # Test 3: Check that BPF program is cleaned up.

        # Delete the container.
        run_crun_command(["delete", "-f", cid])
        cid = None
        if os.path.exists(bpf_path):
            logger.info("BPF program `%s` still exist after crun delete", prog_file)
            return -1

        return 0

    except Exception as e:
        logger.info("Test failed with exception: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

all_tests = {
    "bpf-devices-systemd": test_bpf_devices_systemd,
}

if __name__ == "__main__":
    tests_main(all_tests)
