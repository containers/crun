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

import time
import json
import subprocess
import os
import shutil
import sys
from tests_utils import *

def test_userns_full_mapping():
    if is_rootless():
        return 77
    conf = base_config()
    add_all_namespaces(conf)

    fullMapping = [
        {
            "containerID": 0,
            "hostID": 0,
            "size": 4294967295
        }
    ]

    conf['linux']['uidMappings'] = fullMapping
    conf['linux']['gidMappings'] = fullMapping

    for filename in ['uid_map', 'gid_map']:
        conf['process']['args'] = ['/init', 'cat', '/proc/self/%s' % filename]
        out, _ = run_and_get_output(conf)
        proc_status = parse_proc_status(out)

        if "4294967295" not in out:
            return -1

    return 0


def test_uid():
    if is_rootless():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['uid'] = 1000
    out, _ = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    ids = proc_status['Uid'].split()
    for i in ids:
        if i != "1000":
            return -1
    return 0

def test_gid():
    if is_rootless():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['gid'] = 1000
    out, _ = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    ids = proc_status['Gid'].split()
    for i in ids:
        if i != "1000":
            return -1
    return 0

def test_no_groups():
    if is_rootless():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['gid'] = 1000
    out, _ = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    ids = proc_status['Groups'].split()
    if len(ids) > 0:
        return -1
    return 0

def test_keep_groups():
    if is_rootless():
        return 77
    oldgroups = os.getgroups()
    out = ""
    try:
        os.setgroups([1,2,3,4,5])
        conf = base_config()
        conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
        add_all_namespaces(conf)
        conf['annotations'] = {}
        conf['annotations']['run.oci.keep_original_groups'] = "1"
        out, _ = run_and_get_output(conf)
    finally:
        os.setgroups(oldgroups)

    proc_status = parse_proc_status(out)
    ids = proc_status['Groups'].split()
    if len(ids) == 0:
        return -1
    return 0

all_tests = {
    "uid" : test_uid,
    "gid" : test_gid,
    "userns-full-mapping" : test_userns_full_mapping,
    "no-groups" : test_no_groups,
    "keep-groups" : test_keep_groups,
}

if __name__ == "__main__":
    tests_main(all_tests)
