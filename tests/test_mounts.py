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
from tests_utils import *
import tempfile

try:
    import libmount
except Exception:
    print("1..0")
    sys.exit(0)

def helper_mount(options, tmpfs=True):
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    if tmpfs:
        mount_opt = {"destination": "/var/dir", "type": "tmpfs", "source": "tmpfs", "options": [options]}
    else:
        mount_opt = {"destination": "/var/dir", "type": "bind", "source": get_tests_root(), "options": ["bind", "rprivate"] + [options]}
    conf['mounts'].append(mount_opt)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    with tempfile.NamedTemporaryFile(mode='w', delete=True) as f:
        f.write(out)
        f.flush()
        t = libmount.Table(f.name)
        m = t.find_target('/var/dir')
        return [m.vfs_options, m.fs_options]
    return -1

def test_mount_symlink():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    mount_opt = {"destination": "/etc/localtime", "type": "bind", "source": "/etc/localtime", "options": ["bind", "ro"]}
    conf['mounts'].append(mount_opt)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    if "Rome" in out:
        return 0
    return -1

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

def test_mount_path_with_multiple_slashes():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    mount_opt = {"destination": "/test//test", "type": "bind", "source": "/tmp", "options": ["bind"]}
    conf['mounts'].append(mount_opt)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    if "test/test" in out:
        return 0
    return -1

def test_mount_ro():
    a = helper_mount("ro")[0]
    if "ro" not in a:
        return -1
    a = helper_mount("ro", tmpfs=False)[0]
    if "ro" not in a:
        return -1
    return 0

def test_mount_rw():
    a = helper_mount("rw", tmpfs=False)[0]
    if "rw" not in a:
        return -1
    a = helper_mount("rw")[0]
    if "rw" not in a:
        return -1
    return 0

def test_mount_relatime():
    a = helper_mount("relatime", tmpfs=False)[0]
    if "relatime" not in a:
        return -1
    a = helper_mount("relatime")[0]
    if "relatime" not in a:
        return -1
    return 0

def test_mount_strictatime():
    a = helper_mount("strictatime", tmpfs=False)[0]
    if "relatime" not in a:
        return 0
    a = helper_mount("strictatime")[0]
    if "relatime" not in a:
        return 0
    return -1

def test_mount_exec():
    a = helper_mount("exec", tmpfs=False)[0]
    if "noexec" in a:
        return -1
    a = helper_mount("exec")[0]
    if "noexec" in a:
        return -1
    return 0

def test_mount_noexec():
    a = helper_mount("noexec", tmpfs=False)[0]
    if "noexec" not in a:
        return -1
    a = helper_mount("noexec")[0]
    if "noexec" not in a:
        return -1
    return 0

def test_mount_suid():
    a = helper_mount("suid", tmpfs=False)[0]
    if "nosuid" in a:
        return -1
    a = helper_mount("suid")[0]
    if "nosuid" in a:
        return -1
    return 0

def test_mount_nosuid():
    a = helper_mount("nosuid", tmpfs=False)[0]
    if "nosuid" not in a:
        return -1
    a = helper_mount("nosuid")[0]
    if "nosuid" not in a:
        return -1
    return 0

def test_mount_sync():
    a = helper_mount("sync")[1]
    if "sync" not in a:
        return -1
    return 0

def test_mount_dirsync():
    a = helper_mount("dirsync")[1]
    if "dirsync" not in a:
        return -1
    return 0

def test_mount_nodev():
    a = helper_mount("nodev", tmpfs=False)[0]
    if "nodev" not in a:
        return -1
    a = helper_mount("nodev")[0]
    if "nodev" not in a:
        return -1
    return 0

def test_mount_dev():
    a = helper_mount("dev", tmpfs=False)[0]
    if "nodev" in a:
        return -1
    a = helper_mount("dev")[0]
    if "nodev" in a:
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

        idmapped_mounts_status = subprocess.call(["./tests/init", "check-feature", "idmapped-mounts", source_dir])
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

        def check(mappings, expected):
            conf = copy.deepcopy(template)
            mount_opt = {"destination": "/foo", "type": "bind", "source": source_dir, "options": ["bind", "ro", mappings]}
            conf['mounts'].append(mount_opt)
            out = run_and_get_output(conf, chown_rootfs_to=1)
            if expected not in out[0]:
                sys.stderr.write("wrong file owner, found %s instead of %s" % (out[0], expected))
                return True
            return False

        if check("idmap", "0:0"):
            return 1

        if check("idmap=uids=0-1-10;gids=0-1-10", "0:0"):
            return 1

        if check("idmap=uids=0-2-10#10-100-10;gids=0-1-10", "1:0"):
            return 1

        os.chown(target, 1, 2)
        if check("idmap=uids=@0-1-10;gids=+0-1-10", "2:2"):
            return 1
    finally:
        shutil.rmtree(source_dir)

    return 0

all_tests = {
    "mount-ro" : test_mount_ro,
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
    "mount-symlink-not-existing" : test_mount_symlink_not_existing,
    "mount-dev" : test_mount_dev,
    "mount-nodev" : test_mount_nodev,
    "mount-path-with-multiple-slashes" : test_mount_path_with_multiple_slashes,
    "mount-userns-bind-mount" : test_userns_bind_mount,
    "mount-idmapped-mounts" : test_idmapped_mounts,
}

if __name__ == "__main__":
    tests_main(all_tests)
