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
import subprocess

from tests_utils import *

def run_with_sysctl(key, value):
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/sys/net/ipv4/ip_forward']
    # A user namespace is needed when rootless, but not otherwise: as root,
    # a single mapping for uid 0 may leave the rootfs path inaccessible.
    rootless = is_rootless()
    add_all_namespaces(conf, userns=rootless)
    if rootless:
        conf['linux']['uidMappings'] = [{"containerID": 0, "hostID": os.geteuid(), "size": 1}]
        conf['linux']['gidMappings'] = [{"containerID": 0, "hostID": os.getegid(), "size": 1}]
    conf['linux']['sysctl'] = {key : value}
    # Do not hide stderr, so that the error message can be matched below.
    return run_and_get_output(conf)

def test_sysctl():
    out, _ = run_with_sysctl('net.ipv4.ip_forward', '1')
    if out.strip() != "1":
        logger.info("unexpected value %s" % out)
        return -1
    return 0

def test_sysctl_invalid_path():
    # A sysctl name is turned into a path below /proc/sys, so it must be
    # neither absolute nor contain a ".." component: either way it would
    # name a sysctl other than the one that was validated.
    for key in ['net/../kernel/sysrq',
                'net/..//kernel/sysrq',
                '/net/ipv4/ip_forward',
                '.net.ipv4.ip_forward']:
        try:
            run_with_sysctl(key, '1')
        except subprocess.CalledProcessError as e:
            out = e.output.decode('utf-8', errors='ignore')
            if "contains an invalid path" in out:
                continue
            logger.info("unexpected error for %s: %s" % (key, out))
            return -1
        logger.info("unexpected success for %s" % key)
        return -1
    return 0

all_tests = {
    "sysctl" : test_sysctl,
    "sysctl-invalid-path" : test_sysctl_invalid_path,
}

if __name__ == "__main__":
    tests_main(all_tests)
