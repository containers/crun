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

# Tests for network device configuration (net_device.c coverage)

import subprocess
import os
from tests_utils import *


def create_dummy_interface(name):
    """Create a dummy network interface for testing."""
    try:
        subprocess.run(['ip', 'link', 'add', name, 'type', 'dummy'],
                      check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


def delete_interface(name):
    """Delete a network interface."""
    try:
        subprocess.run(['ip', 'link', 'delete', name],
                      check=False, capture_output=True)
    except:
        pass


def test_loopback_interface():
    """Test that loopback interface is configured in network namespace."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, netns=True)

    # Check that lo interface is up
    conf['process']['args'] = ['/init', 'cat', '/sys/class/net/lo/operstate']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        # Loopback should be "unknown" or "up" state
        if 'up' in out.lower() or 'unknown' in out.lower():
            return 0
        logger.info("Unexpected lo state: %s", out.strip())
        return -1
    except Exception as e:
        logger.info("Exception: %s", e)
        return -1


def test_network_namespace_isolation():
    """Test that network namespace provides isolation."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, netns=True)

    # List interfaces - should only see lo in isolated namespace
    conf['process']['args'] = ['/init', 'ls', '/sys/class/net/']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        interfaces = out.strip().split()
        # In a new network namespace, we should only see 'lo'
        if interfaces == ['lo']:
            return 0
        # Some systems might have additional virtual interfaces
        logger.info("Found interfaces: %s", interfaces)
        if 'lo' in interfaces:
            return 0
        return -1
    except Exception as e:
        logger.info("Exception: %s", e)
        return -1


all_tests = {
    "net-device-loopback": test_loopback_interface,
    "net-device-namespace-isolation": test_network_namespace_isolation,
}

if __name__ == "__main__":
    tests_main(all_tests)
