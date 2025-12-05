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
import shutil
from tests_utils import *

def test_mode_device():
    if is_rootless():
        return (77, "requires root privileges")

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
                sys.stderr.write("# device mode test failed with userns=%s: expected '%s' in output\n" % (have_userns, expected))
                sys.stderr.write("# actual output: %s\n" % out[0])
                sys.stderr.write("# device config: %s\n" % conf['linux']['devices'][0])
                return -1
        except Exception as e:
            sys.stderr.write("# device mode test failed with userns=%s: %s\n" % (have_userns, str(e)))
            return -1
    return 0

def test_owner_device():
    if is_rootless():
        return (77, "requires root privileges")

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
                sys.stderr.write("# device owner test failed with userns=%s: expected '%s' in output\n" % (have_userns, expected))
                sys.stderr.write("# actual output: %s\n" % out[0])
                sys.stderr.write("# device config: %s\n" % conf['linux']['devices'][0])
                return -1
        except Exception as e:
            sys.stderr.write("# device owner test failed with userns=%s: %s\n" % (have_userns, str(e)))
            return -1
    return 0

def test_deny_devices():
    if is_rootless():
        return (77, "requires root privileges")

    try:
        os.stat("/dev/fuse")
    except:
        return (77, "/dev/fuse device not available")

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
        return (77, "/dev/fuse device not available")

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
        sys.stderr.write("# " + str(e) + "\n")
        return -1
    return 0


def test_allow_device():
    if is_rootless():
        return (77, "requires root privileges")

    try:
        os.stat("/dev/fuse")
    except:
        return (77, "/dev/fuse device not available")

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
        return (77, "requires root privileges")

    try:
        os.stat("/dev/fuse")
    except:
        return (77, "/dev/fuse device not available")

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
        return (77, "requires root privileges")

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
        return (77, "requires root privileges")

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'true']
    conf['linux']['devices'] = [{"path": "/mnt/", "type": "b", "major": 10, "minor": 229}]
    try:
        run_and_get_output(conf)
    except Exception as e:
        return -1
    return 0

def test_net_devices():
    if is_rootless():
        return (77, "requires root privileges")

    ip_path = shutil.which("ip")
    if ip_path is None:
        sys.stderr.write("# ip command not found\n")
        return (77, "ip command not found")

    current_netns = os.open("/proc/self/ns/net", os.O_RDONLY)
    try:
        os.unshare(os.CLONE_NEWNET)

        for specify_broadcast in [True, False]:
            for specify_name in [True, False]:
                sys.stderr.write("# test_net_devices: creating testdevice with specify_broadcast=%s, specify_name=%s\n" % (specify_broadcast, specify_name))
                result = subprocess.run(["ip", "link", "add", "testdevice", "type", "dummy"], capture_output=True, text=True)
                if result.returncode != 0:
                    sys.stderr.write("# ip link add failed: %s\n" % result.stderr)
                    return -1
                if specify_broadcast:
                    result = subprocess.run(["ip", "addr", "add", "10.1.2.3/24", "brd", "10.1.2.254", "dev", "testdevice"], capture_output=True, text=True)
                    if result.returncode != 0:
                        sys.stderr.write("# ip addr add with broadcast failed: %s\n" % result.stderr)
                        return -1
                else:
                    result = subprocess.run(["ip", "addr", "add", "10.1.2.3/24", "dev", "testdevice"], capture_output=True, text=True)
                    if result.returncode != 0:
                        sys.stderr.write("# ip addr add without broadcast failed: %s\n" % result.stderr)
                        return -1

                conf = base_config()
                add_all_namespaces(conf)

                # Add network capabilities needed for network device operations
                conf['process']['capabilities'] = {
                    "bounding": [
                        "CAP_NET_ADMIN",
                        "CAP_NET_RAW",
                        "CAP_SYS_ADMIN"
                    ],
                    "effective": [
                        "CAP_NET_ADMIN",
                        "CAP_NET_RAW",
                        "CAP_SYS_ADMIN"
                    ],
                    "inheritable": [
                        "CAP_NET_ADMIN",
                        "CAP_NET_RAW",
                        "CAP_SYS_ADMIN"
                    ],
                    "permitted": [
                        "CAP_NET_ADMIN",
                        "CAP_NET_RAW",
                        "CAP_SYS_ADMIN"
                    ]
                }
                if specify_name:
                    conf['process']['args'] = ['/init', 'ip', 'newtestdevice']
                    conf['linux']['netDevices'] = {
                        "testdevice": {
                            "name": "newtestdevice"
                        }
                    }
                else:
                    conf['process']['args'] = ['/init', 'ip', 'testdevice']
                    conf['linux']['netDevices'] = {
                        "testdevice": {
                        }
                    }

                try:
                    out = run_and_get_output(conf)
                    sys.stderr.write("# test_net_devices: specify_broadcast=%s, specify_name=%s\n" % (specify_broadcast, specify_name))
                    sys.stderr.write("# test_net_devices: output: %s\n" % repr(out[0]))
                    if "address: 10.1.2.3" not in out[0]:
                        sys.stderr.write("# address not found in output\n")
                        sys.stderr.write("# full output: %s\n" % repr(out[0]))
                        return 1
                    if specify_broadcast:
                        if "broadcast: 10.1.2.254" not in out[0]:
                            sys.stderr.write("# broadcast address not found in output\n")
                            sys.stderr.write("# full output: %s\n" % repr(out[0]))
                            return 1
                    else:
                        if "broadcast" in out[0]:
                            sys.stderr.write("# broadcast address found in output when it shouldn't be\n")
                            sys.stderr.write("# full output: %s\n" % repr(out[0]))
                            return 1
                except Exception as e:
                    sys.stderr.write("# test_net_devices exception: %s\n" % str(e))
                    return -1
                finally:
                    # Clean up the test device
                    subprocess.run(["ip", "link", "del", "testdevice"], capture_output=True)
    finally:
        os.setns(current_netns, os.CLONE_NEWNET)
        os.close(current_netns)

    return 0

def test_mknod_fifo_device():
    if is_rootless():
        return (77, "requires root privileges")

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'isfifo', '/dev/testfifo']
    conf['linux']['devices'] = [
        {"path": "/dev/testfifo", "type": "p", "fileMode": 0o0660, "uid": 1, "gid": 2}
    ]
    try:
        run_and_get_output(conf)
    except Exception as e:
        sys.stderr.write("# test_mknod_fifo_device failed: %s\n" % e)
        return -1
    return 0

def test_mknod_char_device():
    if is_rootless():
        return (77, "requires root privileges")

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'ischar', '/dev/testchar']
    conf['linux']['devices'] = [
        {"path": "/dev/testchar", "type": "c", "major": 251, "minor": 1, "fileMode": 0o0640, "uid": 3, "gid": 4}
    ]
    try:
        run_and_get_output(conf)
    except Exception as e:
        sys.stderr.write("# test_mknod_char_device failed: {e}\n")
        return -1
    return 0

def test_allow_device_read_only():
    if is_rootless():
        return (77, "requires root privileges")

    try:
        # Best effort load
        subprocess.run(["modprobe", "null_blk", "nr_devices=1"])
    except:
        pass
    try:
        st = os.stat("/dev/nullb0")
        major, minor = os.major(st.st_rdev), os.minor(st.st_rdev)
    except:
        return (77, "/dev/nullb0 device not available")

    conf = base_config()
    add_all_namespaces(conf)

    conf['linux']['devices'] = [{
        "path": "/dev/controlledchar",
        "type": "b",
        "major": major,
        "minor": minor,
        "fileMode": 0o0666
    }]
    conf['linux']['resources'] = {
        "devices": [
            {"allow": False, "access": "rwm"},
            {"allow": True, "type": "b", "major": major, "minor": minor, "access": "r"},
        ]
    }

    conf['process']['args'] = ['/init', 'open', '/dev/controlledchar']
    try:
        run_and_get_output(conf)
    except Exception as e:
        sys.stderr.write("# test_allow_device_read_only failed: %s\n" % e)
        return -1

    conf['process']['args'] = ['/init', 'openwronly', '/dev/controlledchar']
    try:
        run_and_get_output(conf)
        sys.stderr.write("# test_allow_device_read_only: write access was unexpectedly allowed.\n")
        return 1
    except Exception as e:
        output_str = getattr(e, 'output', b'').decode(errors='ignore')
        if "Operation not permitted" in output_str or "Permission denied" in output_str:
            return 0
        else:
            sys.stderr.write("# test_allow_device_read_only (write attempt) failed with: %s, output: %s\n" % (e, output_str))
            return 1

    return 1

all_tests = {
    "mknod-fifo-device": test_mknod_fifo_device,
    "mknod-char-device": test_mknod_char_device,
    "allow-device-read-only": test_allow_device_read_only,
    "owner-device" : test_owner_device,
    "deny-devices" : test_deny_devices,
    "allow-device" : test_allow_device,
    "allow-access" : test_allow_access,
    "mknod-device" : test_mknod_device,
    "mode-device"  : test_mode_device,
    "create-or-bind-mount-device" : test_create_or_bind_mount_device,
    "handle-device-trailing-slash" : test_trailing_slash_mknod_device,
    "net-devices" : test_net_devices,
}

if __name__ == "__main__":
    tests_main(all_tests)
