#!/bin/env python3
# crun - OCI runtime written in C
#
# Copyright (C) 2017, 2018, 2019, 2025 Giuseppe Scrivano <giuseppe@scrivano.org>
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
import sys
from tests_utils import *

def test_userns_full_mapping():
    if is_rootless():
        return (77, "requires root privileges")
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
        out, _ = run_and_get_output(conf, hide_stderr=True)
        proc_status = parse_proc_status(out)

        if "4294967295" not in out:
            return -1

    return 0

def test_uid():
    if is_rootless():
        return (77, "requires root privileges")
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['uid'] = 1000
    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)

    ids = proc_status['Uid'].split()
    for i in ids:
        if i != "1000":
            return -1
    return 0

def test_gid():
    if is_rootless():
        return (77, "requires root privileges")
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['gid'] = 1000
    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)

    ids = proc_status['Gid'].split()
    for i in ids:
        if i != "1000":
            return -1
    return 0

def test_no_groups():
    if is_rootless():
        return (77, "requires root privileges")
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['gid'] = 1000
    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)

    ids = proc_status['Groups'].split()
    if len(ids) > 0:
        return -1
    return 0

def test_keep_groups():
    if is_rootless():
        return (77, "requires root privileges")
    oldgroups = os.getgroups()
    out = ""
    try:
        os.setgroups([1,2,3,4,5])
        conf = base_config()
        conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
        add_all_namespaces(conf)
        conf['annotations'] = {}
        conf['annotations']['run.oci.keep_original_groups'] = "1"
        out, _ = run_and_get_output(conf, hide_stderr=True)
    finally:
        os.setgroups(oldgroups)

    proc_status = parse_proc_status(out)
    ids = proc_status['Groups'].split()
    if len(ids) == 0:
        return -1
    return 0

def test_additional_gids():
    if is_rootless():
        return (77, "requires root privileges")
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['uid'] = 1000
    conf['process']['user']['gid'] = 1000
    conf['process']['user']['additionalGids'] = [2000, 3000]
    out, _ = run_and_get_output(conf, hide_stderr=True)
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

    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)

    if 'Umask' not in proc_status:
        return -1

    umask_from_status = proc_status['Umask']

    if umask_from_status != test_umask_octal_str:
        return -2

    return 0

def test_dev_null_no_chown():
    """Test that /dev/null file descriptors are not chowned to container user."""
    if is_rootless():
        return (77, "requires root privileges")

    # Get current owner of /dev/null and use owner + 1 as container user
    dev_null_stat = os.stat('/dev/null')
    container_uid = dev_null_stat.st_uid + 1
    container_gid = dev_null_stat.st_gid + 1

    conf = base_config()
    conf['process']['user'] = {"uid": container_uid, "gid": container_gid}
    add_all_namespaces(conf)

    # Check ownership of stdin fd which should be /dev/null
    conf['process']['args'] = ['/init', 'owner', '/proc/self/fd/0']

    try:
        out, container_id = run_and_get_output(conf, hide_stderr=True, stdin_dev_null=True)
        logger.info("Container ran successfully, output: %s", out)
        if ':' in out:
            uid_str, gid_str = out.strip().split(':')
            uid, gid = int(uid_str), int(gid_str)
            # Should NOT be owned by container user
            if uid == container_uid or gid == container_gid:
                logger.info("dev-null-no-chown test failed: /dev/null fd owned by container user %d:%d", container_uid, container_gid)
                logger.info("stdout: %s", out)
                return -1
            logger.info("dev-null-no-chown test passed: /dev/null fd owned by %d:%d (not container user %d:%d)", uid, gid, container_uid, container_gid)
        else:
            logger.info("dev-null-no-chown test failed: unexpected owner output format")
            logger.info("stdout: %s", out)
            return -1
        return 0
    except Exception as e:
        logger.info("dev-null-no-chown test failed with exception: %s", e)
        if hasattr(e, 'output'):
            logger.info("command output: %s", e.output)
        return -1

def test_regular_files_chowned():
    """Test that regular file descriptors are chowned to container user."""
    if is_rootless():
        return (77, "requires root privileges")

    # Get current owner of /dev/null and use owner + 1 as container user
    dev_null_stat = os.stat('/dev/null')
    container_uid = dev_null_stat.st_uid + 1
    container_gid = dev_null_stat.st_gid + 1

    conf = base_config()
    conf['process']['user'] = {"uid": container_uid, "gid": container_gid}
    add_all_namespaces(conf)

    # Check ownership of regular stdout (not /dev/null)
    conf['process']['args'] = ['/init', 'owner', '/proc/self/fd/1']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if ':' in out:
            uid_str, gid_str = out.strip().split(':')
            uid, gid = int(uid_str), int(gid_str)
            # Should be owned by container user
            if uid != container_uid or gid != container_gid:
                logger.info("regular-files-chowned test failed: regular fd owned by %d:%d (expected %d:%d)", uid, gid, container_uid, container_gid)
                return -1
            logger.info("regular-files-chowned test passed: regular fd owned by %d:%d (container user)", uid, gid)
        else:
            logger.info("regular-files-chowned test failed: unexpected output format: %s", out)
            return -1
        return 0
    except Exception as e:
        logger.info("regular-files-chowned test failed with exception: %s", e)
        return -1

all_tests = {
    "uid" : test_uid,
    "gid" : test_gid,
    "userns-full-mapping" : test_userns_full_mapping,
    "no-groups" : test_no_groups,
    "keep-groups" : test_keep_groups,
    "additional-gids": test_additional_gids,
    "umask": test_umask,
    "dev-null-no-chown": test_dev_null_no_chown,
    "regular-files-chowned": test_regular_files_chowned,
}

if __name__ == "__main__":
    tests_main(all_tests)
