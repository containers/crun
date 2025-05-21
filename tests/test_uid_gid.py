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
from tests_utils import *

def test_userns_full_mapping():
    if is_rootless():
        return 77
    conf = base_config()
    add_all_namespaces(conf, userns=True)

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

def test_additional_gids():
    if is_rootless():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['uid'] = 1000
    conf['process']['user']['gid'] = 1000
    conf['process']['user']['additionalGids'] = [2000, 3000]
    out, _ = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    gids_status = proc_status['Gid'].split()
    for g_id in gids_status:
        if g_id != "1000":
            return -1

    groups_str = proc_status.get('Groups', "")
    actual_supplementary_groups = set()
    if groups_str:
        actual_supplementary_groups = set(groups_str.split())

    expected_supplementary_groups = {"2000", "3000"}

    if actual_supplementary_groups != expected_supplementary_groups:
        return -2
    return 0

def test_umask():
    if is_rootless():
        pass

    conf = base_config()
    add_all_namespaces(conf)

    test_umask_octal_str = "0027"
    test_umask_int = 0o027

    conf['process']['user']['umask'] = test_umask_int
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']

    out, _ = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    if 'Umask' not in proc_status:
        return -1

    umask_from_status = proc_status['Umask']

    if umask_from_status != test_umask_octal_str:
        return -2

    return 0

all_tests = {
    "uid" : test_uid,
    "gid" : test_gid,
    "userns-full-mapping" : test_userns_full_mapping,
    "no-groups" : test_no_groups,
    "keep-groups" : test_keep_groups,
    "additional-gids": test_additional_gids,
    "umask": test_umask,
}

if __name__ == "__main__":
    tests_main(all_tests)
