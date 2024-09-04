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

def test_mode_device():
    if is_rootless():
        return 77

    # verify the umask doesn't affect the result
    os.umask(0o22)

    for have_userns in [True, False]:
        conf = base_config()
        add_all_namespaces(conf, userns=have_userns)
        if have_userns:
            fullMapping = [
                {
                    "containerID": 0,
                    "hostID": 0,
                    "size": 4294967295
                }
            ]
            conf['linux']['uidMappings'] = fullMapping
            conf['linux']['gidMappings'] = fullMapping

        conf['process']['args'] = ['/init', 'mode', '/dev/foo']
        conf['linux']['devices'] = [{"path": "/dev/foo", "type": "b", "major": 1, "minor": 5, "uid": 10, "gid": 11, "fileMode": 0o157},]
        try:
            expected = "157"
            out = run_and_get_output(conf)
            if expected not in out[0]:
                sys.stderr.write("wrong file mode, found %s instead of %s with userns=%s" % (out[0], expected, have_userns))
                return True
            return False
        except Exception as e:
            print(e)
            return -1
    return 0

def test_owner_device():
    if is_rootless():
        return 77

    for have_userns in [True, False]:
        conf = base_config()
        add_all_namespaces(conf, userns=have_userns)
        if have_userns:
            fullMapping = [
                {
                    "containerID": 0,
                    "hostID": 0,
                    "size": 4294967295
                }
            ]
            conf['linux']['uidMappings'] = fullMapping
            conf['linux']['gidMappings'] = fullMapping

        conf['process']['args'] = ['/init', 'owner', '/dev/foo']
        conf['linux']['devices'] = [{"path": "/dev/foo", "type": "b", "major": 1, "minor": 5, "uid": 10, "gid": 11},]
        try:
            expected = "10:11"
            out = run_and_get_output(conf)
            if expected not in out[0]:
                sys.stderr.write("wrong file owner, found %s instead of %s with userns=%s" % (out[0], expected, have_userns))
                return True
            return False
        except Exception as e:
            return -1
    return 0

def test_deny_devices():
    if is_rootless():
        return 77

    try:
        os.stat("/dev/fuse")
    except:
        return 77

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'open', '/dev/fuse']
    conf['linux']['resources'] = {"devices": [{"allow": False, "access": "rwm"}]}
    dev = {
	"destination": "/dev",
	"type": "bind",
	"source": "/dev",
	"options": [
            "rbind",
	    "rw"
	]
    }
    conf['mounts'].append(dev)
    try:
        run_and_get_output(conf)
    except Exception as e:
        if "Operation not permitted" in e.output.decode():
            return 0
    return -1

def test_create_or_bind_mount_device():
    try:
        os.stat("/dev/fuse")
    except:
        return 77

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'access', '/dev/fuse']
    conf['linux']['devices'] = [{ "path": "/dev/fuse",
                                 "type": "c",
                                 "major": 10,
                                 "minor": 229,
                                 "fileMode": 0o775,
                                 "uid": 0,
                                 "gid": 0
                                }]
    try:
        run_and_get_output(conf)
    except Exception as e:
        sys.stderr.write(str(e) + "\n")
        return -1
    return 0


def test_allow_device():
    if is_rootless():
        return 77

    try:
        os.stat("/dev/fuse")
    except:
        return 77

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'open', '/dev/fuse']
    conf['linux']['resources'] = {"devices": [{"allow": False, "access": "rwm"},
                                              {"allow": True, "type": "c", "major": 10, "minor": 229, "access": "r"}]}
    dev = {
	"destination": "/dev",
	"type": "bind",
	"source": "/dev",
	"options": [
            "rbind",
	    "rw"
	]
    }
    conf['mounts'].append(dev)
    try:
        run_and_get_output(conf)
    except Exception as e:
        return -1
    return 0

def test_allow_access():
    if is_rootless():
        return 77

    try:
        os.stat("/dev/fuse")
    except:
        return 77

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'access', '/dev/fuse']
    conf['linux']['resources'] = {"devices": [{"allow": False, "access": "rwm"},
                                              {"allow": True, "type": "c", "major": 10, "minor": 229, "access": "rw"}]}
    dev = {
	"destination": "/dev",
	"type": "bind",
	"source": "/dev",
	"options": [
            "rbind",
	    "rw"
	]
    }
    conf['mounts'].append(dev)
    try:
        run_and_get_output(conf)
    except Exception as e:
        return -1
    return 0

def test_mknod_device():
    if is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'true']
    conf['linux']['devices'] = [{"path": "/foo-dev", "type": "b", "major": 10, "minor": 229},
                                {"path": "/subdir/foo-dev", "type": "b", "major": 10, "minor": 229},]
    try:
        run_and_get_output(conf)
    except Exception as e:
        return -1
    return 0

def test_trailing_slash_mknod_device():
    if is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'true']
    conf['linux']['devices'] = [{"path": "/mnt/", "type": "b", "major": 10, "minor": 229}]
    try:
        run_and_get_output(conf)
    except Exception as e:
        return -1
    return 0

all_tests = {
    "owner-device" : test_owner_device,
    "deny-devices" : test_deny_devices,
    "allow-device" : test_allow_device,
    "allow-access" : test_allow_access,
    "mknod-device" : test_mknod_device,
    "mode-device"  : test_mode_device,
    "create-or-bind-mount-device" : test_create_or_bind_mount_device,
    "handle-device-trailing-slash" : test_trailing_slash_mknod_device,
}

if __name__ == "__main__":
    tests_main(all_tests)
