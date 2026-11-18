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
import tempfile
import time
from tests_utils import *

# The error of an update on a scope whose device filter is generated from its rules, used when the kernel cannot load
# the filter that reads its rules from a map.
LEGACY_UPDATE_ERROR = "updating device access list not supported when using BPFProgram"

def kernel_supports_map_filter():
    """The device filter that reads its rules from a map needs bounded loops, supported since Linux 5.3"""
    try:
        major, minor = os.uname().release.split('.')[:2]
        return (int(major), int(minor)) >= (5, 3)
    except ValueError:
        return False

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
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True, cgroup_manager="systemd")

        # Get systemd scope.
        state = run_crun_command(['state', cid])
        scope = json.loads(state)['systemd-scope']

        # Test 1: Check that BPFProgram property is set on the scope.

        output = subprocess.check_output(['systemctl', 'show', '-PBPFProgram', scope], close_fds=False).decode().strip()
        if output == "":
            logger.info("BPFProgram property not found or empty")
            return -1

        # Should look like "device:/sys/fs/bpf/crun/devices-XXXXXXXXXXXXXXXX" for the program shared by the containers,
        # or "device:/sys/fs/bpf/crun/crun-xxx_scope" for the program generated for the container.
        if "device:/sys/fs/bpf/crun/" not in output:
            logger.info("Bad BPFProgram property value: `%s`", output)
            return -1

        # Test 2: Check that BPF program file was created.

        # Extract the path.
        bpf_path = output.split("device:", 1)[1]
        if not os.path.exists(bpf_path):
            logger.info("BPF program file `%s` not found", bpf_path)
            return -1

        # Test 3: Check that the program of the container is cleaned up, and that the shared one is not.
        shared = os.path.basename(bpf_path).startswith("devices-")

        # Delete the container.
        run_crun_command(["delete", "-f", cid])
        cid = None
        if shared and not os.path.exists(bpf_path):
            logger.info("The shared BPF program `%s` was removed by crun delete", bpf_path)
            return -1
        if not shared and os.path.exists(bpf_path):
            logger.info("BPF program `%s` still exist after crun delete", bpf_path)
            return -1

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "eBPF" in output or "BPF" in output:
            return (77, "eBPF device filter not supported")
        logger.info("Test failed with exception: %s", e)
        return -1
    except Exception as e:
        logger.info("Test failed with exception: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

def test_bpf_devices_deny_all_allow_null():
    """Test BPF device filter: deny all, allow /dev/null"""
    ret = check_bpf_prerequisites()
    if ret != 0:
        return ret

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # Deny all devices, then allow /dev/null (1:3)
    conf['linux']['resources'] = {
        'devices': [
            {'allow': False, 'access': 'rwm'},
            {'allow': True, 'type': 'c', 'major': 1, 'minor': 3, 'access': 'rwm'}
        ]
    }

    # Try to read /dev/null - should succeed
    conf['process']['args'] = ['/init', 'cat', '/dev/null']

    cid = None
    try:
        out, cid = run_and_get_output(conf, hide_stderr=False, cgroup_manager="systemd")
        return 0
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "eBPF" in output or "BPF" in output:
            return (77, "eBPF device filter not supported")
        logger.info("Test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("Test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_bpf_devices_wildcard_major():
    """Test BPF device filter with wildcard major number"""
    ret = check_bpf_prerequisites()
    if ret != 0:
        return ret

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # Allow all character devices with major 1 (null, zero, etc.)
    conf['linux']['resources'] = {
        'devices': [
            {'allow': False, 'access': 'rwm'},
            {'allow': True, 'type': 'c', 'major': 1, 'access': 'rwm'}
        ]
    }

    conf['process']['args'] = ['/init', 'cat', '/dev/null']

    cid = None
    try:
        out, cid = run_and_get_output(conf, hide_stderr=False, cgroup_manager="systemd")
        return 0
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "eBPF" in output or "BPF" in output:
            return (77, "eBPF device filter not supported")
        logger.info("Test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("Test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_bpf_devices_block_device():
    """Test BPF device filter for block devices"""
    ret = check_bpf_prerequisites()
    if ret != 0:
        return ret

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # Allow block devices
    conf['linux']['resources'] = {
        'devices': [
            {'allow': False, 'access': 'rwm'},
            {'allow': True, 'type': 'b', 'access': 'r'}
        ]
    }

    conf['process']['args'] = ['/init', 'true']

    cid = None
    try:
        out, cid = run_and_get_output(conf, hide_stderr=False, cgroup_manager="systemd")
        return 0
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "eBPF" in output or "BPF" in output:
            return (77, "eBPF device filter not supported")
        logger.info("Test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("Test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


DENY_ALL = {'allow': False, 'access': 'rwm'}


def make_fuse_config(devices):
    """A container that pauses, with /dev/fuse (10:229) that is not one of the default devices"""
    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['linux']['devices'] = [{'path': '/dev/fuse', 'type': 'c', 'major': 10, 'minor': 229, 'fileMode': 0o666}]
    conf['linux']['resources'] = {'devices': devices}
    conf['process']['args'] = ['/init', 'pause']
    return conf


def can_open_fuse(cid):
    # Only an open that succeeds means that the access is allowed, and EPERM that the cgroup denies it.
    try:
        run_crun_command_raw(['exec', cid, '/init', 'open', '/dev/fuse'])
        return True
    except subprocess.CalledProcessError as e:
        if b'Operation not permitted' in (e.output or b''):
            return False
        raise


def update_devices(cid, devices):
    with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
        json.dump({'devices': devices}, f)
        f.flush()
        run_crun_command_raw(['update', '--resources', f.name, cid])


def check_prerequisites(cgroup_manager):
    if cgroup_manager == "systemd":
        return check_bpf_prerequisites()

    if is_rootless():
        return (77, "requires root privileges")

    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    return 0


def run_bpf_devices_update(cgroup_manager):
    """Update the device list of a running container, both loosening and tightening it"""
    ret = check_prerequisites(cgroup_manager)
    if ret != 0:
        return ret

    allow_dev = {'allow': True, 'type': 'c', 'major': 10, 'minor': 229, 'access': 'r'}

    cid = None
    try:
        _, cid = run_and_get_output(make_fuse_config([DENY_ALL]), hide_stderr=False, command='run', detach=True,
                                    cgroup_manager=cgroup_manager)

        if can_open_fuse(cid):
            logger.info("/dev/fuse is accessible before the update")
            return -1

        update_devices(cid, [DENY_ALL, allow_dev])
        if not can_open_fuse(cid):
            logger.info("/dev/fuse is not accessible after allowing it")
            return -1

        update_devices(cid, [DENY_ALL])
        if can_open_fuse(cid):
            logger.info("/dev/fuse is accessible after denying it again")
            return -1

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if cgroup_manager == "systemd" and LEGACY_UPDATE_ERROR in output and not kernel_supports_map_filter():
            return (77, "the kernel does not support the device filter that reads its rules from a map")
        logger.info("Test failed with exception: %s: %s", e, output)
        return -1
    except Exception as e:
        logger.info("Test failed with exception: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


# The kernel charges the memory used to verify the device filter to the memory cgroup of crun, that can be the cgroup
# of a pod with a small limit.
MEMORY_LIMIT = 4 * 1024 * 1024


def count_oom_kills(cgroup):
    with open(os.path.join(cgroup, "memory.events")) as f:
        for line in f:
            if line.startswith("oom_kill "):
                return int(line.split()[1])
    return 0


def crun_uses_sanitizers():
    try:
        out = subprocess.check_output(["ldd", get_crun_path()], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
    except (OSError, subprocess.CalledProcessError):
        return False
    return "libasan" in out or "libubsan" in out


def run_bpf_devices_memory_limit(cgroup_manager):
    """Create a container from a process in a cgroup with a small memory limit"""
    ret = check_prerequisites(cgroup_manager)
    if ret != 0:
        return ret

    with open("/sys/fs/cgroup/cgroup.subtree_control") as f:
        if "memory" not in f.read().split():
            return (77, "the memory controller is not enabled")

    if crun_uses_sanitizers():
        return (77, "the memory overhead of the sanitizers exceeds the limit")

    cgroup = "/sys/fs/cgroup/crun-test-memory-limit-%d" % os.getpid()
    wrapper = os.path.join(get_tests_root(), "crun-memory-limit")
    old_runtime = os.environ.get("OCI_RUNTIME")
    crun = get_crun_path()
    cid = None
    try:
        os.mkdir(cgroup)
        with open(os.path.join(cgroup, "memory.max"), "w") as f:
            f.write(str(MEMORY_LIMIT))
        if os.path.exists(os.path.join(cgroup, "memory.swap.max")):
            with open(os.path.join(cgroup, "memory.swap.max"), "w") as f:
                f.write("0")

        with open(wrapper, "w") as f:
            f.write("#!/bin/sh\necho $$ > %s/cgroup.procs || exit 1\nexec %s \"$@\"\n" % (cgroup, crun))
        os.chmod(wrapper, 0o755)

        conf = base_config()
        add_all_namespaces(conf, cgroupns=True)
        conf['linux']['resources'] = {'devices': [DENY_ALL, {'allow': True, 'type': 'c', 'major': 1, 'minor': 3, 'access': 'rw'}]}
        conf['process']['args'] = ['/init', 'cat', '/dev/null']

        os.environ["OCI_RUNTIME"] = wrapper
        try:
            _, cid = run_and_get_output(conf, hide_stderr=False, cgroup_manager=cgroup_manager)
        finally:
            if old_runtime is None:
                del os.environ["OCI_RUNTIME"]
            else:
                os.environ["OCI_RUNTIME"] = old_runtime

        if count_oom_kills(cgroup) != 0:
            logger.info("crun was killed by the OOM killer with memory.max=%d", MEMORY_LIMIT)
            return -1
        return 0
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        logger.info("Test failed with exception: %s: %s (OOM kills: %d)", e, output, count_oom_kills(cgroup))
        return -1
    except Exception as e:
        logger.info("Test failed with exception: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        if os.path.exists(cgroup):
            for _ in range(50):
                try:
                    os.rmdir(cgroup)
                    break
                except OSError:
                    time.sleep(0.1)


def test_bpf_devices_memory_limit_systemd():
    """Test creating a container with a small memory limit with the systemd cgroup manager"""
    return run_bpf_devices_memory_limit("systemd")


def test_bpf_devices_memory_limit_cgroupfs():
    """Test creating a container with a small memory limit with the cgroupfs cgroup manager"""
    return run_bpf_devices_memory_limit("cgroupfs")


def run_bpf_devices_too_many_rules(cgroup_manager):
    """A list of device rules that does not fit in the table of the filter is an error on create and on update"""
    ret = check_prerequisites(cgroup_manager)
    if ret != 0:
        return ret

    # With the default devices, the list does not fit in the 1024 rules of the table.
    too_many = [DENY_ALL] + [{'allow': True, 'type': 'c', 'major': 1000 + i, 'minor': 0, 'access': 'r'} for i in range(1024)]

    cid = 'test-bpf-too-many-%d' % os.getpid()

    def delete():
        subprocess.call([get_crun_path(), "--root", get_tests_root_status(), "delete", "-f", cid],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        try:
            run_and_get_output(make_fuse_config(too_many), hide_stderr=False, command='run', detach=True,
                               cgroup_manager=cgroup_manager, id_container=cid)
            logger.info("the container was created with too many device rules")
            return -1
        except subprocess.CalledProcessError as e:
            output = e.output.decode('utf-8', errors='ignore') if e.output else ''
            if "too many device rules" not in output:
                logger.info("unexpected error on create: %s", output)
                return -1
        finally:
            delete()

        run_and_get_output(make_fuse_config([DENY_ALL]), hide_stderr=False, command='run', detach=True,
                           cgroup_manager=cgroup_manager, id_container=cid)

        try:
            update_devices(cid, too_many)
            logger.info("the device list was updated with too many device rules")
            return -1
        except subprocess.CalledProcessError as e:
            output = e.output.decode('utf-8', errors='ignore') if e.output else ''
            if "too many device rules" not in output:
                logger.info("unexpected error on update: %s", output)
                return -1

        # The previous rules are still in place.
        if can_open_fuse(cid):
            logger.info("/dev/fuse is accessible after the failed update")
            return -1

        return 0

    except Exception as e:
        logger.info("Test failed with exception: %s", e)
        return -1
    finally:
        delete()


def test_bpf_devices_too_many_rules_systemd():
    """Test that too many device rules is an error with the systemd cgroup manager"""
    return run_bpf_devices_too_many_rules("systemd")


def test_bpf_devices_too_many_rules_cgroupfs():
    """Test that too many device rules is an error with the cgroupfs cgroup manager"""
    return run_bpf_devices_too_many_rules("cgroupfs")


def test_bpf_devices_update_systemd():
    """Test updating the device list of a running container with the systemd cgroup manager"""
    return run_bpf_devices_update("systemd")


def test_bpf_devices_update_cgroupfs():
    """Test updating the device list of a running container with the cgroupfs cgroup manager"""
    return run_bpf_devices_update("cgroupfs")


# A second device that is not one of the default devices, its major is reserved for local use so it has no driver.
LOCAL_DEVICE = {'path': '/dev/crun-test-local', 'type': 'c', 'major': 60, 'minor': 7, 'fileMode': 0o666}

# The error when the cgroup has no filter that reads its rules from a map.
NO_MAP_FILTER_ERROR = "no eBPF device filter that can be updated"


def can_open_device(cid, path):
    # The open of a device without a driver that is allowed fails with ENXIO or ENODEV.
    try:
        run_crun_command_raw(['exec', cid, '/init', 'open', path])
        return True
    except subprocess.CalledProcessError as e:
        if b'Operation not permitted' in (e.output or b''):
            return False
        if b'No such device' in (e.output or b''):
            return True
        raise


def run_with_local_device(cgroup_manager):
    conf = make_fuse_config([DENY_ALL])
    conf['linux']['devices'].append(LOCAL_DEVICE)
    _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True, cgroup_manager=cgroup_manager)
    return cid


def check_access(cid, fuse, local):
    ok = True
    for path, expected in (('/dev/fuse', fuse), (LOCAL_DEVICE['path'], local)):
        allowed = can_open_device(cid, path)
        if allowed != expected:
            logger.info("%s is %s", path, "accessible" if allowed else "not accessible")
            ok = False
    return ok


def add_device_error(e, cgroup_manager):
    output = e.output.decode('utf-8', errors='ignore') if e.output else ''
    if NO_MAP_FILTER_ERROR in output and not kernel_supports_map_filter():
        return (77, "the kernel does not support the device filter that reads its rules from a map")
    logger.info("Test failed with exception: %s: %s", e, output)
    return -1


def run_bpf_devices_add_device(cgroup_manager):
    """Add a device to the device list of a running container with --add-device, and remove it with --remove-device"""
    ret = check_prerequisites(cgroup_manager)
    if ret != 0:
        return ret

    cid = None
    try:
        cid = run_with_local_device(cgroup_manager)
        if not check_access(cid, fuse=False, local=False):
            return -1

        # The rule is not shadowed by the rule that denies every device.
        run_crun_command_raw(['update', '--add-device=c 10:229 rwm', cid])
        if not check_access(cid, fuse=True, local=False):
            return -1

        # The same rule again.
        run_crun_command_raw(['update', '--add-device', 'c 10:229 rwm', cid])
        if not check_access(cid, fuse=True, local=False):
            return -1

        run_crun_command_raw(['update', '--remove-device=c 10:229', cid])
        if not check_access(cid, fuse=False, local=False):
            return -1

        # The last rule has the highest priority.
        run_crun_command_raw(['update', '--remove-device=c *:* rw', '--add-device=c 10:229 rw', cid])
        if not check_access(cid, fuse=True, local=False):
            return -1

        # The rule is added after the resources of the file are set.
        with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
            json.dump({'devices': [DENY_ALL]}, f)
            f.flush()
            run_crun_command_raw(['update', '--resources', f.name, '--add-device=c 60:7 rw', cid])
        if not check_access(cid, fuse=False, local=True):
            return -1

        return 0

    except subprocess.CalledProcessError as e:
        return add_device_error(e, cgroup_manager)
    except Exception as e:
        logger.info("Test failed with exception: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def run_bpf_devices_add_device_concurrent(cgroup_manager):
    """Two concurrent --add-device updates of the same container both survive"""
    ret = check_prerequisites(cgroup_manager)
    if ret != 0:
        return ret

    cid = None
    try:
        cid = run_with_local_device(cgroup_manager)

        for _ in range(20):
            update_devices(cid, [DENY_ALL])
            if not check_access(cid, fuse=False, local=False):
                return -1

            procs = []
            for rule in ('c 10:229 rwm', 'c 60:7 rwm'):
                args = [get_crun_path(), "--root", get_tests_root_status(), 'update', '--add-device', rule, cid]
                procs.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT))
            for p in procs:
                out, _ = p.communicate()
                if p.returncode != 0:
                    raise subprocess.CalledProcessError(p.returncode, p.args, out)

            if not check_access(cid, fuse=True, local=True):
                return -1

        return 0

    except subprocess.CalledProcessError as e:
        return add_device_error(e, cgroup_manager)
    except Exception as e:
        logger.info("Test failed with exception: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def run_bpf_devices_add_device_bad_syntax(cgroup_manager):
    """An invalid rule for --add-device or --remove-device is an error and changes nothing"""
    ret = check_prerequisites(cgroup_manager)
    if ret != 0:
        return ret

    bad_rules = ["", "c", "c 10", "c 10:", "c :229", "x 10:229", "cc 10:229", "c 10:229 rwx", "c 10:229 rr",
                 "c 10:229 rwm x", "c -1:229", "c 10:0x1", "c 4294967296:1", "a 10:229", "a *:1 rwm"]

    cid = None
    try:
        cid = run_with_local_device(cgroup_manager)

        for option in ('--add-device', '--remove-device'):
            for rule in bad_rules:
                # A valid rule given with the invalid one is not added either.
                try:
                    run_crun_command_raw(['update', '--add-device=c 60:7 rwm', '%s=%s' % (option, rule), cid])
                    logger.info("the rule `%s` for %s is accepted", rule, option)
                    return -1
                except subprocess.CalledProcessError as e:
                    output = e.output.decode('utf-8', errors='ignore') if e.output else ''
                    if "invalid device rule" not in output:
                        logger.info("unexpected error for `%s`: %s", rule, output)
                        return -1

        if not check_access(cid, fuse=False, local=False):
            return -1

        return 0

    except subprocess.CalledProcessError as e:
        return add_device_error(e, cgroup_manager)
    except Exception as e:
        logger.info("Test failed with exception: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_bpf_devices_add_device_systemd():
    """Test --add-device with the systemd cgroup manager"""
    return run_bpf_devices_add_device("systemd")


def test_bpf_devices_add_device_cgroupfs():
    """Test --add-device with the cgroupfs cgroup manager"""
    return run_bpf_devices_add_device("cgroupfs")


def test_bpf_devices_add_device_concurrent_systemd():
    """Test concurrent --add-device updates with the systemd cgroup manager"""
    return run_bpf_devices_add_device_concurrent("systemd")


def test_bpf_devices_add_device_concurrent_cgroupfs():
    """Test concurrent --add-device updates with the cgroupfs cgroup manager"""
    return run_bpf_devices_add_device_concurrent("cgroupfs")


def test_bpf_devices_add_device_bad_syntax_systemd():
    """Test an invalid --add-device rule with the systemd cgroup manager"""
    return run_bpf_devices_add_device_bad_syntax("systemd")


def test_bpf_devices_add_device_bad_syntax_cgroupfs():
    """Test an invalid --add-device rule with the cgroupfs cgroup manager"""
    return run_bpf_devices_add_device_bad_syntax("cgroupfs")


all_tests = {
    "bpf-devices-systemd": test_bpf_devices_systemd,
    "bpf-devices-deny-all-allow-null": test_bpf_devices_deny_all_allow_null,
    "bpf-devices-wildcard-major": test_bpf_devices_wildcard_major,
    "bpf-devices-block-device": test_bpf_devices_block_device,
    "bpf-devices-memory-limit-systemd": test_bpf_devices_memory_limit_systemd,
    "bpf-devices-memory-limit-cgroupfs": test_bpf_devices_memory_limit_cgroupfs,
    "bpf-devices-update-systemd": test_bpf_devices_update_systemd,
    "bpf-devices-update-cgroupfs": test_bpf_devices_update_cgroupfs,
    "bpf-devices-too-many-rules-systemd": test_bpf_devices_too_many_rules_systemd,
    "bpf-devices-too-many-rules-cgroupfs": test_bpf_devices_too_many_rules_cgroupfs,
    "bpf-devices-add-device-systemd": test_bpf_devices_add_device_systemd,
    "bpf-devices-add-device-cgroupfs": test_bpf_devices_add_device_cgroupfs,
    "bpf-devices-add-device-concurrent-systemd": test_bpf_devices_add_device_concurrent_systemd,
    "bpf-devices-add-device-concurrent-cgroupfs": test_bpf_devices_add_device_concurrent_cgroupfs,
    "bpf-devices-add-device-bad-syntax-systemd": test_bpf_devices_add_device_bad_syntax_systemd,
    "bpf-devices-add-device-bad-syntax-cgroupfs": test_bpf_devices_add_device_bad_syntax_cgroupfs,
}

if __name__ == "__main__":
    tests_main(all_tests)
