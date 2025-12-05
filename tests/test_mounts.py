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

import sys
import copy
import socket
from tests_utils import *
import tempfile
import re
from typing import List, Optional

try:
    import libmount
except Exception:
    print("1..0")
    sys.exit(0)

def helper_mount(options: str, tmpfs: bool = True, userns: bool = False, is_file: bool = False) -> List[Optional[str]]:
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf, userns=userns)
    source_file = os.path.join(get_tests_root(), "a-file")
    if is_file:
        with open(source_file, 'w'):
            pass
        mount_opt = {"destination": "/var/file", "type": "bind", "source": source_file, "options": ["bind", "rprivate"] + [options]}
    elif tmpfs:
        mount_opt = {"destination": "/var/dir", "type": "tmpfs", "source": "tmpfs", "options": [options]}
    else:
        mount_opt = {"destination": "/var/dir", "type": "bind", "source": get_tests_root(), "options": ["bind", "rprivate"] + [options]}
    conf['mounts'].append(mount_opt)
    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        with tempfile.NamedTemporaryFile(mode='w', delete=True) as f:
            f.write(out)
            f.flush()
            t = libmount.Table(f.name)
            target = '/var/file' if is_file else '/var/dir'
            m = t.find_target(target)
            if m is None:
                sys.stderr.write("# helper_mount failed: mount target '%s' not found in mountinfo\n" % target)
                sys.stderr.write("# mount options: %s, tmpfs=%s, userns=%s, is_file=%s\n" % (options, tmpfs, userns, is_file))
                sys.stderr.write("# mountinfo output: %s\n" % out[:300])
                return [None, None]
            return [m.vfs_options, m.fs_options]
    except Exception as e:
        sys.stderr.write("# helper_mount failed with exception: %s\n" % str(e))
        sys.stderr.write("# mount options: %s, tmpfs=%s, userns=%s, is_file=%s\n" % (options, tmpfs, userns, is_file))
        return [None, None]

def test_mount_symlink():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    mount_opt = {"destination": "/etc/localtime", "type": "bind", "source": "/etc/localtime", "options": ["bind", "ro"]}
    conf['mounts'].append(mount_opt)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    if "Rome" in out:
        return 0
    sys.stderr.write("# symlink mount test failed: expected 'Rome' in mountinfo output\n")
    sys.stderr.write("# actual output: %s\n" % out[:200])
    return -1

def test_mount_fifo():
    conf = base_config()
    conf['process']['args'] = ['/init', 'type', '/fifo']
    add_all_namespaces(conf)

    source_file = os.path.join(get_tests_root(), "a-fifo")

    os.mkfifo(source_file)

    for options in ([], ["ro"], ["rro"]):
        mount_opt = {"destination": "/fifo", "type": "bind", "source": source_file, "options": options + ["bind"]}
        conf['mounts'].append(mount_opt)
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if "FIFO" not in out:
            sys.stderr.write("# FIFO mount test failed with options %s: expected 'FIFO' in output\n" % options)
            sys.stderr.write("# actual output: %s\n" % out)
            return 1
    return 0

def test_mount_unix_socket():
    conf = base_config()
    conf['process']['args'] = ['/init', 'type', '/unix-socket']
    add_all_namespaces(conf)

    source_file = os.path.join(get_tests_root(), "unix-socket")

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(source_file)

    for options in ([], ["ro"], ["rro"]):
        mount_opt = {"destination": "/unix-socket", "type": "bind", "source": source_file, "options": options + ["bind"]}
        conf['mounts'].append(mount_opt)
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if "socket" not in out:
            sys.stderr.write("# unix socket mount test failed with options %s: expected 'socket' in output\n" % options)
            sys.stderr.write("# actual output: %s\n" % out)
            return 1
    return 0

def test_mount_tmpfs_permissions():
    def prepare_rootfs(rootfs):
        path = os.path.join(rootfs, "test-tmpfs")
        os.mkdir(path)
        os.chmod(path, 0o712)

    conf = base_config()
    conf['process']['args'] = ['/init', 'mode', '/test-tmpfs']
    add_all_namespaces(conf)
    conf['mounts'].append({"destination": "/test-tmpfs", "type": "tmpfs", "source": "tmpfs", "options": ["ro"]})
    out, _ = run_and_get_output(conf, hide_stderr=True, callback_prepare_rootfs=prepare_rootfs)
    if "712" in out:
        return 0
    sys.stderr.write("# tmpfs permissions test failed: expected '712' in mode output\n")
    sys.stderr.write("# actual output: %s\n" % out)
    return -1

def test_mount_bind_to_rootfs():
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)
    tmpdir = tempfile.mkdtemp()
    shutil.copy(get_init_path(), tmpdir)

    mounts = [
        {"destination": "/", "type": "bind", "source": tmpdir, "options": ["bind"]},
    ]
    conf['mounts'] = mounts + conf['mounts']
    _, _ = run_and_get_output(conf, hide_stderr=True)
    return 0

def test_mount_tmpfs_to_rootfs():
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)
    tmpdir = tempfile.mkdtemp()

    mounts = [
        {"destination": "/", "type": "tmpfs", "source": "tmpfs", "options": ["tmpcopyup"]},
    ]
    conf['mounts'] = mounts + conf['mounts']
    _, _ = run_and_get_output(conf, hide_stderr=True)
    return 0

def test_ro_cgroup():
    for cgroupns in [True, False]:
        for netns in [True, False]:
            for has_cgroup_mount in [True, False]:
                conf = base_config()
                conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
                add_all_namespaces(conf, cgroupns=cgroupns, netns=netns)
                mounts = [
                    {
	                "destination": "/sys",
	                "type": "sysfs",
	                "source": "sysfs",
	                "options": [
		            "nosuid",
		            "noexec",
		            "nodev",
		            "ro"
	                ]
	            },
                    {
	                "destination": "/proc",
	                "type": "proc"
	            }
                ]

                if has_cgroup_mount:
                    mounts.append({
                        "destination": "/sys/fs/cgroup",
                        "type": "cgroup",
                        "source": "cgroup",
                        "options": [
                            "nosuid",
                            "noexec",
                            "nodev",
                            "relatime",
                            "ro"
                        ]
                    })

                conf['mounts'] = mounts
                out, _ = run_and_get_output(conf, hide_stderr=True)
                for i in reversed(out.split("\n")):
                    if i.find("/sys/fs/cgroup") >= 0:
                        if i.find("ro,") < 0:
                            print("fail with cgroupns=%s, netns=%s and cgroup_mount=%s, got %s" % (cgroupns, netns, has_cgroup_mount, i), file=sys.stderr)
                            return -1
                        break
    return 0

def test_mount_symlink_not_existing():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    mount_opt = {"destination": "/etc/not-existing", "type": "bind", "source": "/etc/localtime", "options": ["bind", "ro"]}
    conf['mounts'].append(mount_opt)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    if "foo/bar" in out:
        return 0
    return -1

def test_mount_readonly_should_inherit_options_from_parent():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    mount_opt = {"destination": "/test", "type": "bind", "source": "/tmp", "options": ["rbind", "nosuid","noexec","nodev"]}
    conf['mounts'].append(mount_opt)
    mount_opt = {"destination": "/test/world", "type": "bind", "source": "/etc", "options": ["rbind", "nosuid","noexec","nodev"]}
    conf['mounts'].append(mount_opt)

    # Move test/world to a readonly path
    conf['linux']['readonlyPaths'] = ["/test/world"]
    out, _ = run_and_get_output(conf, hide_stderr=True)

    # final mount info must contain /test/world which is converted to readonly
    # but also inherits the flags from its parent
    if "/test/world ro,nosuid,nodev,noexec,relatime" in out:
        return 0
    return -1

def test_proc_readonly_should_inherit_options_from_parent():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    for mount in conf['mounts']:
        if mount['destination'] == "/proc":
           mount['options'] = ["nosuid", "noexec","nodev"]

    # Move `/proc/bus` to a readonly path
    conf['linux']['readonlyPaths'] = ["/proc/bus"]
    out, _ = run_and_get_output(conf, hide_stderr=True)

    # final mount info must contain /proc/bus which is converted to readonly
    # but also inherits the flags from /proc
    if "/proc/bus ro,nosuid,nodev,noexec,relatime" in out:
        return 0
    return -1

def test_copy_symlink():
    root = get_tests_root()
    symlink = os.path.join(root, "a-broken-link")
    target = "point-to-nowhere"

    os.symlink(target, symlink)

    conf = base_config()
    conf['process']['args'] = ['/init', 'readlink', '/a/sym/link']
    add_all_namespaces(conf)
    mount_opt = {"destination": "/a/sym/link", "type": "bind", "source": symlink, "options": ["rbind", "copy-symlink"]}
    conf['mounts'].append(mount_opt)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    if target in out:
        return 0
    return -1

def test_mount_path_with_multiple_slashes():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    mount_opt = {"destination": "/test//test", "type": "bind", "source": "/tmp", "options": ["rbind"]}
    conf['mounts'].append(mount_opt)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    if "test/test" in out:
        return 0
    return -1

def test_mount_ro():
    for userns in [True, False]:
        a = helper_mount("ro", userns=userns, is_file=True)[0]
        if a is None or "ro" not in a:
            return -1
        a = helper_mount("ro", userns=userns)[0]
        if a is None or "ro" not in a:
            return -1
        a = helper_mount("ro", userns=userns, tmpfs=False)[0]
        if a is None or "ro" not in a:
            return -1
    return 0

def test_mount_rro():
    for userns in [True, False]:
        a = helper_mount("rro", userns=userns, is_file=True)[0]
        if a is None or "ro" not in a:
            return -1
        a = helper_mount("rro", userns=userns)[0]
        if a is None or "ro" not in a:
            return -1
        a = helper_mount("rro", userns=userns, tmpfs=False)[0]
        if a is None or "ro" not in a:
            return -1
    return 0

def test_mount_rw():
    for userns in [True, False]:
        a = helper_mount("rw", tmpfs=False, userns=userns)[0]
        if a is None or "rw" not in a:
            return -1
        a = helper_mount("rw", userns=userns, is_file=True)[0]
        if a is None or "rw" not in a:
            return -1
        a = helper_mount("rw", userns=userns)[0]
        if a is None or "rw" not in a:
            return -1
    return 0

def test_mount_relatime():
    for userns in [True, False]:
        a = helper_mount("relatime", tmpfs=False, userns=userns)[0]
        if a is None or "relatime" not in a:
            return -1
        a = helper_mount("relatime", is_file=True, userns=userns)[0]
        if a is None or "relatime" not in a:
            return -1
        a = helper_mount("relatime", userns=userns)[0]
        if a is None or "relatime" not in a:
            return -1
    return 0

def test_mount_strictatime():
    for userns in [True, False]:
        a = helper_mount("strictatime", is_file=True, userns=userns)[0]
        if a is None or "relatime" not in a:
            return 0
        a = helper_mount("strictatime", tmpfs=False, userns=userns)[0]
        if a is None or "relatime" not in a:
            return 0
        a = helper_mount("strictatime", userns=userns)[0]
        if a is None or "relatime" not in a:
            return 0
    return -1

def test_mount_exec():
    for userns in [True, False]:
        a = helper_mount("exec", is_file=True, userns=userns)[0]
        if a is not None and "noexec" in a:
            return -1
        a = helper_mount("exec", tmpfs=False, userns=userns)[0]
        if a is not None and "noexec" in a:
            return -1
        a = helper_mount("exec", userns=userns)[0]
        if a is not None and "noexec" in a:
            return -1
    return 0

def test_mount_noexec():
    for userns in [True, False]:
        a = helper_mount("noexec", is_file=True, userns=userns)[0]
        if a is None or "noexec" not in a:
            return -1
        a = helper_mount("noexec", tmpfs=False, userns=userns)[0]
        if a is None or "noexec" not in a:
            return -1
        a = helper_mount("noexec", userns=userns)[0]
        if a is None or "noexec" not in a:
            return -1
    return 0

def test_mount_suid():
    for userns in [True, False]:
        a = helper_mount("suid", is_file=True, userns=userns)[0]
        if a is not None and "nosuid" in a:
            return -1
        a = helper_mount("suid", tmpfs=False, userns=userns)[0]
        if a is not None and "nosuid" in a:
            return -1
        a = helper_mount("suid", userns=userns)[0]
        if a is not None and "nosuid" in a:
            return -1
    return 0

def test_mount_nosuid():
    for userns in [True, False]:
        a = helper_mount("nosuid", is_file=True, userns=userns)[0]
        if a is None or "nosuid" not in a:
            return -1
        a = helper_mount("nosuid", tmpfs=False, userns=userns)[0]
        if a is None or "nosuid" not in a:
            return -1
        a = helper_mount("nosuid", userns=userns)[0]
        if a is None or "nosuid" not in a:
            return -1
    return 0

def test_mount_sync():
    for userns in [True, False]:
        a = helper_mount("sync", userns=userns)[1]
        if a is None or "sync" not in a:
            return -1
    return 0

def test_mount_dirsync():
    for userns in [True, False]:
        a = helper_mount("dirsync", userns=userns)[1]
        if a is None or "dirsync" not in a:
            return -1
    return 0

def test_mount_nodev():
    for userns in [True, False]:
        a = helper_mount("nodev", is_file=True)[0]
        if a is None or "nodev" not in a:
            return -1
        a = helper_mount("nodev", tmpfs=False)[0]
        if a is None or "nodev" not in a:
            return -1
        a = helper_mount("nodev", userns=userns)[0]
        if a is None or "nodev" not in a:
            return -1
    return 0

def test_mount_dev():
    for userns in [True, False]:
        a = helper_mount("dev", userns=userns, tmpfs=False)[0]
        if a is not None and "nodev" in a:
            return -1
        a = helper_mount("dev", userns=userns, is_file=True)[0]
        if a is not None and "nodev" in a:
            return -1
        a = helper_mount("dev", userns=userns)[0]
        if a is not None and "nodev" in a:
            return -1
    return 0

def test_userns_bind_mount():
    if is_rootless():
        return 77
    conf = base_config()
    add_all_namespaces(conf, userns=True)

    fullMapping = [
        {
            "containerID": 0,
            "hostID": 1,
            "size": 10
        }
    ]
    conf['linux']['uidMappings'] = fullMapping
    conf['linux']['gidMappings'] = fullMapping

    bind_dir_parent = os.path.join(get_tests_root(), "bind-mount-userns")
    bind_dir = os.path.join(bind_dir_parent, "m")
    try:
        os.makedirs(bind_dir)
        mount_opt = {"destination": "/foo", "type": "bind", "source": bind_dir, "options": ["bind", "ro"]}
        conf['mounts'].append(mount_opt)
        os.chown(bind_dir_parent, 0, 0)
        os.chmod(bind_dir_parent, 0o000)

        conf['process']['args'] = ['/init', 'true']
        run_and_get_output(conf, chown_rootfs_to=1)
    finally:
        shutil.rmtree(bind_dir)
    return 0

def test_userns_bind_mount_symlink():
    if is_rootless():
        return 77
    conf = base_config()
    add_all_namespaces(conf, userns=True)

    fullMapping = [
        {
            "containerID": 0,
            "hostID": 1,
            "size": 10
        }
    ]
    conf['linux']['uidMappings'] = fullMapping
    conf['linux']['gidMappings'] = fullMapping
    sys.stderr.write("# start\n")

    bind_dir_parent = os.path.join(get_tests_root(), "bind-mount-userns-symlink")
    bind_dir = os.path.join(bind_dir_parent, "m")
    bind_dir_symlink = os.path.join(bind_dir_parent, "s")
    try:
        os.makedirs(bind_dir)
        os.symlink(bind_dir, bind_dir_symlink)
        with open(os.path.join(bind_dir, "content"), "w+") as f:
            f.write("hello")
        mount_opt = {"destination": "/foo", "type": "bind", "source": bind_dir_symlink, "options": ["bind", "ro"]}
        conf['mounts'].append(mount_opt)
        os.chown(bind_dir_parent, 0, 0)
        os.chmod(bind_dir_parent, 0o000)

        conf['process']['args'] = ['/init', 'cat', "/foo/content"]
        out, _ = run_and_get_output(conf, chown_rootfs_to=1)
        if out != "hello":
            sys.stderr.write("# wrong file owner, found %s instead of %s\n" % (out, "hello"))
            return -1
    finally:
        shutil.rmtree(bind_dir)
    return 0

def test_idmapped_mounts():
    if is_rootless():
        return 77
    source_dir = os.path.join(get_tests_root(), "test-idmapped-mounts")
    try:
        os.makedirs(source_dir)
        target = os.path.join(source_dir, "file")

        with open(target, "w+") as f:
            f.write("")
        os.chown(target, 0, 0)

        idmapped_mounts_status = subprocess.call([get_init_path(), "check-feature", "idmapped-mounts", source_dir])
        if idmapped_mounts_status != 0:
            return 77

        template = base_config()
        add_all_namespaces(template, userns=True)
        fullMapping = [
            {
                "containerID": 0,
                "hostID": 1,
                "size": 10
            }
        ]
        template['linux']['uidMappings'] = fullMapping
        template['linux']['gidMappings'] = fullMapping
        template['process']['args'] = ['/init', 'owner', '/foo/file']

        def check(uidMappings, gidMappings, recursive, expected):
            # to properly check recursive we'd need to add a mount on the host.  But we don't want to perform
            # any mount on the host, so we just check that the recursive option at least doesn't fail and works
            # as a regular idmapped mount.
            conf = copy.deepcopy(template)
            idmapOption = "ridmap" if recursive else "idmap"
            options = ["bind", "ro", idmapOption]

            mount_opt = {"destination": "/foo", "type": "bind", "source": source_dir, "options": options}

            if uidMappings is not None:
                mount_opt["uidMappings"] = uidMappings
            if gidMappings is not None:
                mount_opt["gidMappings"] = gidMappings

            conf['mounts'].append(mount_opt)
            out = run_and_get_output(conf, chown_rootfs_to=1)
            if expected not in out[0]:
                sys.stderr.write("# wrong file owner, found %s instead of %s\n" % (out[0], expected))
                return True
            return False

        # and now test with uidMappings and gidMappings
        os.chown(target, 0, 0)

        mountMappings = [
            {
                "containerID": 0,
                "hostID": 1,
                "size": 10
            }
        ]
        if check(mountMappings, mountMappings, False, "0:0"):
            return 1
        if check(mountMappings, mountMappings, True, "0:0"):
            return 1

        mountMappings = [
            {
                "containerID": 0,
                "hostID": 2,
                "size": 10
            }
        ]
        if check(mountMappings, mountMappings, False, "1:1"):
            return 1
        if check(mountMappings, mountMappings, True, "1:1"):
            return 1
    finally:
        shutil.rmtree(source_dir)

    return 0

def test_cgroup_mount_without_netns():
    for cgroupns in [True, False]:
        conf = base_config()
        conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
        add_all_namespaces(conf, cgroupns=cgroupns, netns=False)
        mounts = [
            {
	        "destination": "/proc",
	        "type": "proc"
	    },
            {
	        "destination": "/sys",
	        "type": "bind",
	        "source": "/sys",
	        "options": [
                    "rprivate",
                    "nosuid",
                    "noexec",
                    "nodev",
                    "ro",
                    "rbind"
	        ]
	    },
            {
                "destination": "/sys/fs/cgroup",
                "type": "cgroup",
                "source": "cgroup",
                "options": [
	            "rprivate",
                    "nosuid",
                    "noexec",
                    "nodev",
                    "rprivate",
                    "relatime",
                    "ro"
                ]
            }
        ]

        conf['mounts'] = mounts

        out, _ = run_and_get_output(conf)
        # print(out)
        # validate there are two mounts
        count = 0
        for i in out.split("\n"):
            if i.find("/sys/fs/cgroup") >= 0:
                count = count + 1
        if count < 2:
            sys.stderr.write("# fail with cgroupns=%s, got %s\n" % (cgroupns, out))
            return -1
    return 0

def test_add_remove_mounts():
    if is_rootless():
        return 77
    conf = base_config()

    conf['mounts'].append({"destination": "/foo", "type": "tmpfs", "source": "tmpfs", "options": ["rw"]})
    add_all_namespaces(conf, userns=True)

    bind_dir = os.path.join(get_tests_root(), "bind-mount")
    test_file = os.path.join(bind_dir, "test")
    os.makedirs(bind_dir)
    with open(test_file, "w+") as f:
        f.write("test")

    parent_dir_in_container = "/foo/bar"

    def check_test_file(expected):
        exists = False
        try:
            out = run_crun_command(["exec", cid, "/init", "cat", os.path.join(parent_dir_in_container, "test")])
            if "test" in out:
                exists = True
        except:
                pass
        if exists == expected:
            return True
        if expected:
            sys.stderr.write("# test file not found\n")
        else:
            sys.stderr.write("# test file found\n")
        return False

    new_mounts = [{"destination": parent_dir_in_container, "type": "bind", "source": bind_dir, "options": ["bind", "ro"]},
                  {"destination": "/foo/tmpfs", "type": "tmpfs", "source": "tmpfs"}]
    mounts_path = os.path.join(get_tests_root(), "mounts.json")
    with open(mounts_path, "w+") as f:
        json.dump(new_mounts, f)

    cid = None
    try:
        conf['process']['args'] = ['/init', 'pause']
        _, cid = run_and_get_output(conf, detach=True)

        if not check_test_file(False):
            return -1
        run_crun_command(["mounts", "add", cid, mounts_path])
        if not check_test_file(True):
            return -1
        out = run_crun_command(["exec", cid, "/init", "cat", "/proc/self/mountinfo"])
        if not re.search(r".*/ /foo/tmpfs .*tmpfs.*", out):
            sys.stderr.write("# /foo/tmpfs not found as a tmpfs\n")
            return -1

        run_crun_command(["mounts", "remove", cid, mounts_path])
        if not check_test_file(False):
            return -1

        out = run_crun_command(["exec", cid, "/init", "cat", "/proc/self/mountinfo"])
        if re.search(r".*/ /foo/tmpfs .*tmpfs.*", out):
            sys.stderr.write("# /foo/tmpfs still mounted\n")
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        shutil.rmtree(bind_dir)
    return 0

def test_mount_help():
    out = run_crun_command(["mounts", "--help"])
    if "Usage: crun [OPTION...] mounts [add|remove] CONTAINER FILE" not in out:
        return -1

    return 0

def test_bind_mount_symlink_nofollow():
    root = get_tests_root()
    file_target = os.path.join(root, "a-file")
    symlink = os.path.join(root, "a-symlink")
    target_content = file_target
    file_target_content = "inside-the-file"

    with open(file_target, "w+") as f:
        f.write(file_target_content)

    os.symlink(target_content, symlink)

    def prepare_rootfs(rootfs):
        path = os.path.join(rootfs, "target")
        os.symlink("point-to-nowhere", path)

    for userns in [True, False]:
        for src_nofollow in [True, False]:
            conf = base_config()
            add_all_namespaces(conf, userns=userns)

            if userns:
                getMapping = lambda x : [
                    {
                        "containerID": 0,
                        "hostID": x,
                        "size": 1
                    }
                ]
                conf['linux']['uidMappings'] = getMapping(os.geteuid())
                conf['linux']['gidMappings'] = getMapping(os.getegid())

            if src_nofollow:
                options = ["bind", "dest-nofollow", "src-nofollow"]
                conf['process']['args'] = ['/init', 'readlink', '/target']
                expected = target_content
            else:
                options = ["bind", "dest-nofollow"]
                conf['process']['args'] = ['/init', 'cat', '/target']
                expected = file_target_content

            mount_opt = {"destination": "/target", "type": "bind", "source": symlink, "options": options}
            conf['mounts'].append(mount_opt)

            try:
                out, _ = run_and_get_output(conf, hide_stderr=True,callback_prepare_rootfs=prepare_rootfs)
                sys.stderr.write("# got output %s with configuration userns=%s, src-nofollow=%s\n" % (out, userns, src_nofollow))
                if expected not in out:
                    return -1
            except Exception as e:
                sys.stderr.write("# error %s\n" % e)
                return -1

    return 0

def test_bind_mount_symlink_nofollow_procfs():
    root = get_tests_root()
    symlink = os.path.join(root, "a-symlink")
    os.symlink("does not matter", symlink)

    conf = base_config()
    add_all_namespaces(conf)

    options = ["bind", "dest-nofollow", "src-nofollow"]
    conf['process']['args'] = ['/init', 'readlink', '/proc/self']

    mount_opt = {"destination": "/proc/self", "type": "bind", "source": symlink, "options": options}
    conf['mounts'].append(mount_opt)

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True,callback_prepare_rootfs=prepare_rootfs)
        return -1
    except Exception as e:
        sys.stderr.write("# error %s\n" % e)
        return 0

    return 0

def test_bind_mount_file_nofollow():
    root = get_tests_root()
    target = os.path.join(root, "a-file")
    target_content = "content-of-file"

    with open(target, "w+") as f:
        f.write(target_content)

    def prepare_rootfs(rootfs):
        path = os.path.join(rootfs, "symlink")
        os.symlink("point-to-nowhere", path)

    for userns in [True, False]:
        for src_nofollow in [True, False]:
            conf = base_config()
            conf['process']['args'] = ['/init', 'cat', '/symlink']
            add_all_namespaces(conf, userns=userns)

            if userns:
                getMapping = lambda x : [
                    {
                        "containerID": 0,
                        "hostID": x,
                        "size": 1
                    }
                ]
                conf['linux']['uidMappings'] = getMapping(os.geteuid())
                conf['linux']['gidMappings'] = getMapping(os.getegid())

            if src_nofollow:
                options = ["bind", "dest-nofollow", "src-nofollow"]
            else:
                options = ["bind", "dest-nofollow"]
            mount_opt = {"destination": "/symlink", "type": "bind", "source": target, "options": options}
            conf['mounts'].append(mount_opt)

            try:
                out, _ = run_and_get_output(conf, hide_stderr=True,callback_prepare_rootfs=prepare_rootfs)
                sys.stderr.write("# got output %s with configuration userns=%s, src-nofollow=%s\n" % (out, userns, src_nofollow))
                if target_content not in out:
                    return 1
            except Exception as e:
                sys.stderr.write("# error %s\n" % e)
    return 0

def test_idmapped_mounts_without_userns():
    if is_rootless():
        return 77
    source_dir = os.path.join(get_tests_root(), "test-idmapped-mounts-no-userns")
    try:
        os.makedirs(source_dir)
        target = os.path.join(source_dir, "file")

        with open(target, "w+") as f:
            f.write("")
        os.chown(target, 0, 0)

        conf = base_config()
        add_all_namespaces(conf, userns=False)
        conf['process']['args'] = ['/init', 'owner', '/foo/file']

        mountMappings = [
            {
                "containerID": 0,
                "hostID": 1000,
                "size": 10
            }
        ]

        options = ["bind", "ro", "idmap"]
        mount_opt = {"destination": "/foo", "type": "bind", "source": source_dir, "options": options}
        mount_opt["uidMappings"] = mountMappings
        mount_opt["gidMappings"] = mountMappings

        conf['mounts'].append(mount_opt)
        out, _ = run_and_get_output(conf, hide_stderr=True)

        if "1000:1000" not in out:
            sys.stderr.write("# idmap without userns test failed: expected '1000:1000' in output\n")
            sys.stderr.write("# actual output: %s\n" % out)
            return 1
    finally:
        shutil.rmtree(source_dir)

    return 0

all_tests = {
    "mount-ro" : test_mount_ro,
    "mount-rro" : test_mount_rro,
    "mount-rw" : test_mount_rw,
    "mount-relatime" : test_mount_relatime,
    "mount-strictatime" : test_mount_strictatime,
    "mount-exec" : test_mount_exec,
    "mount-noexec" : test_mount_noexec,
    "mount-suid" : test_mount_suid,
    "mount-nosuid" : test_mount_nosuid,
    "mount-sync" : test_mount_sync,
    "mount-dirsync" : test_mount_dirsync,
    "mount-symlink" : test_mount_symlink,
    "mount-fifo" : test_mount_fifo,
    "mount-unix-socket" : test_mount_unix_socket,
    "mount-symlink-not-existing" : test_mount_symlink_not_existing,
    "mount-dev" : test_mount_dev,
    "mount-bind-to-rootfs": test_mount_bind_to_rootfs,
    "mount-tmpfs-to-rootfs": test_mount_tmpfs_to_rootfs,
    "mount-nodev" : test_mount_nodev,
    "mount-path-with-multiple-slashes" : test_mount_path_with_multiple_slashes,
    "mount-userns-bind-mount" : test_userns_bind_mount,
    "mount-idmapped-mounts" : test_idmapped_mounts,
    "mount-idmapped-mounts-without-userns" : test_idmapped_mounts_without_userns,
    "mount-idmapped-mounts-symlink" : test_userns_bind_mount_symlink,
    "mount-linux-readonly-should-inherit-flags": test_mount_readonly_should_inherit_options_from_parent,
    "proc-linux-readonly-should-inherit-flags": test_proc_readonly_should_inherit_options_from_parent,
    "mount-ro-cgroup": test_ro_cgroup,
    "mount-cgroup-without-netns": test_cgroup_mount_without_netns,
    "mount-copy-symlink": test_copy_symlink,
    "mount-bind-mount-symlink-nofollow-procfs": test_bind_mount_symlink_nofollow_procfs,
    "mount-bind-mount-symlink-nofollow": test_bind_mount_symlink_nofollow,
    "mount-bind-mount-file-nofollow": test_bind_mount_file_nofollow,
    "mount-tmpfs-permissions": test_mount_tmpfs_permissions,
    "mount-add-remove-mounts": test_add_remove_mounts,
    "mount-help": test_mount_help,
}

if __name__ == "__main__":
    tests_main(all_tests)
