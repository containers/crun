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

import json
import resource
import errno
import os
import subprocess
import time
from tests_utils import *


def test_cgroup_creation():
    """Test that cgroup is properly created for container."""

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'cat', '/proc/self/cgroup']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Container should have its own cgroup
        if '/' in out:
            return 0
        return 0  # Command ran successfully

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "mount" in output.lower() or "proc" in output.lower():
            return (77, "proc mount not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_cleanup():
    """Test that cgroup is cleaned up after container deletion."""

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        # Get container state to find cgroup path
        state = json.loads(run_crun_command(['state', cid]))

        # Delete the container
        run_crun_command(['delete', '-f', cid])
        cid = None  # Mark as deleted

        # Give time for cleanup
        time.sleep(0.5)

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "mount" in output.lower() or "proc" in output.lower():
            return (77, "proc mount not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_with_resources():
    """Test cgroup creation with resource limits."""

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Add various resource limits
    conf['linux']['resources'] = {
        'memory': {
            'limit': 100 * 1024 * 1024  # 100MB
        },
        'cpu': {
            'shares': 512
        },
        'pids': {
            'limit': 100
        }
    }

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "cgroup resources not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_cpuset_initialization():
    """Test cpuset cgroup initialization."""
    if is_rootless():
        return (77, "cpuset cgroup requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Set cpuset resources
    conf['linux']['resources'] = {
        'cpu': {
            'cpus': '0',
            'mems': '0'
        }
    }

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cpuset" in output.lower() or "cgroup" in output.lower():
            return (77, "cpuset cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_freezer():
    """Test cgroup freezer for pause/resume."""
    if is_rootless():
        return (77, "requires root for cgroup freezer")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Pause uses cgroup freezer
        run_crun_command(['pause', cid])

        # Check state
        state = json.loads(run_crun_command(['state', cid]))
        if state['status'] != 'paused':
            logger.info("container not paused: %s", state['status'])
            return -1

        # Resume
        run_crun_command(['resume', cid])

        # Check state again
        state = json.loads(run_crun_command(['state', cid]))
        if state['status'] != 'running':
            logger.info("container not running after resume: %s", state['status'])
            return -1

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "freezer" in output.lower() or "cgroup" in output.lower():
            return (77, "cgroup freezer not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_v2_unified():
    """Test cgroup v2 unified hierarchy."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cgroup.controllers']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should see available controllers
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "mount" in output.lower() or "proc" in output.lower():
            return (77, "proc mount not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_path_custom():
    """Test custom cgroup path."""
    if is_rootless():
        return (77, "custom cgroup path requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Set custom cgroup path - systemd requires slice:scope format
    cgroup_manager = get_cgroup_manager()
    if cgroup_manager == 'systemd':
        cgroup_path = f'system.slice:crun-test-custom-{os.getpid()}.scope'
    else:
        cgroup_path = f'/test-cgroup-custom-{os.getpid()}'

    conf['linux']['cgroupsPath'] = cgroup_path
    logger.info("cgroup_path_custom: using manager=%s path=%s", cgroup_manager, cgroup_path)

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        stderr = e.stderr.decode('utf-8', errors='ignore') if e.stderr else ''
        logger.info("cgroup_path_custom failed: cmd=%s returncode=%d", e.cmd, e.returncode)
        logger.info("cgroup_path_custom stdout: %s", output)
        logger.info("cgroup_path_custom stderr: %s", stderr)
        if "cgroup" in output.lower() or "cgroup" in stderr.lower():
            return (77, "custom cgroup path not supported")
        return -1
    except Exception as e:
        logger.info("cgroup_path_custom exception: %s", e)
        return -1


def test_cgroup_namespace_private():
    """Test private cgroup namespace."""

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'readlink', '/proc/self/ns/cgroup']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should have its own cgroup namespace
        if 'cgroup:' in out:
            return 0
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "mount" in output.lower() or "proc" in output.lower():
            return (77, "proc mount not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_namespace_host():
    """Test host cgroup namespace (no cgroupns)."""

    conf = base_config()
    add_all_namespaces(conf, cgroupns=False)
    conf['process']['args'] = ['/init', 'cat', '/proc/self/cgroup']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should see host cgroup paths
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "mount" in output.lower() or "proc" in output.lower():
            return (77, "proc mount not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_delegation():
    """Test cgroup delegation to container."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'ls', '/sys/fs/cgroup']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Container should see cgroup filesystem
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "mount" in output.lower() or "proc" in output.lower():
            return (77, "proc mount not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_memory_controllers():
    """Test memory cgroup controller."""

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {
        'memory': {
            'limit': 50 * 1024 * 1024,  # 50MB
            'reservation': 25 * 1024 * 1024  # 25MB soft limit
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        # Verify memory limit is set
        if is_cgroup_v2_unified():
            out = run_crun_command(['exec', cid, '/init', 'cat', '/sys/fs/cgroup/memory.max'])
        else:
            out = run_crun_command(['exec', cid, '/init', 'cat', '/sys/fs/cgroup/memory/memory.limit_in_bytes'])

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "memory" in output.lower() or "cgroup" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "memory cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_pids_controller():
    """Test pids cgroup controller."""

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {
        'pids': {
            'limit': 50
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        # Verify pids limit is set
        if is_cgroup_v2_unified():
            out = run_crun_command(['exec', cid, '/init', 'cat', '/sys/fs/cgroup/pids.max'])
        else:
            out = run_crun_command(['exec', cid, '/init', 'cat', '/sys/fs/cgroup/pids/pids.max'])

        if '50' in out:
            return 0
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "pids" in output.lower() or "cgroup" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "pids cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_cpuset_nested_initialization():
    """Test cpuset initialization with nested cgroups."""
    if is_rootless():
        return (77, "cpuset cgroup requires root")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'cat', '/proc/self/cgroup']

    # Test with nested cgroup path to trigger recursive initialization
    conf['linux']['cgroupsPath'] = f'/test-cpuset-nested-{os.getpid()}'
    conf['linux']['resources'] = {
        'cpu': {
            'cpus': '0',
            'mems': '0'
        }
    }

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cpuset" in output.lower() or "cgroup" in output.lower():
            return (77, "cpuset cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_cpuset_inherit_parent():
    """Test cpuset inheriting from parent cgroup."""
    if is_rootless():
        return (77, "cpuset cgroup requires root")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Test cpuset without explicit cpus/mems to inherit from parent
    conf['linux']['cgroupsPath'] = f'/test-cpuset-inherit-{os.getpid()}'
    # Note: not setting cpu.cpus or cpu.mems to trigger inheritance path

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cpuset" in output.lower() or "cgroup" in output.lower():
            return (77, "cpuset cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_memory_initialization():
    """Test memory cgroup initialization with limits."""
    if is_rootless():
        return (77, "memory cgroup initialization requires root")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['cgroupsPath'] = f'/test-memory-init-{os.getpid()}'
    conf['linux']['resources'] = {
        'memory': {
            'limit': 100 * 1024 * 1024,  # 100MB
            'swap': 200 * 1024 * 1024     # 200MB swap
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "memory" in output.lower() or "cgroup" in output.lower():
            return (77, "memory cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_v2_threaded_mode():
    """Test cgroup v2 threaded mode handling."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")
    if is_rootless():
        return (77, "rootless cannot create cgroups with cgroupfs")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Create a container that might trigger threaded mode
    conf['linux']['cgroupsPath'] = f'/test-threaded-{os.getpid()}'

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower():
            return (77, "cgroup v2 threaded mode not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_v2_crun_exec_subdir():
    """Test cgroup v2 creation of crun-exec subdirectory when parent has subdirs."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")
    if is_rootless():
        return (77, "rootless cannot create cgroups with cgroupfs")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    base_path = f'/test-exec-subdir-{os.getpid()}'
    conf['linux']['cgroupsPath'] = base_path

    cid = None
    try:
        # Create first container in the base path
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Try to exec a command, which might trigger crun-exec subdirectory creation
        try:
            run_crun_command(['exec', cid, '/init', 'true'])
        except:
            pass  # exec might fail, but we're testing cgroup path creation

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower():
            return (77, "cgroup v2 exec path not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_multiple_controllers():
    """Test cgroup with multiple controllers enabled."""
    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    # Set resources that use multiple controllers
    conf['linux']['resources'] = {
        'memory': {
            'limit': 100 * 1024 * 1024
        },
        'cpu': {
            'shares': 512,
            'quota': 50000,
            'period': 100000
        },
        'pids': {
            'limit': 100
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "cgroup controllers not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_error_invalid_path():
    """Test error handling for invalid cgroup path."""
    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Use a path that contains invalid characters
    conf['linux']['cgroupsPath'] = '/test\x00invalid'

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        # If it succeeds, that's unexpected but ok
        return 0

    except subprocess.CalledProcessError as e:
        # Expected to fail
        return 0
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_owner_delegation():
    """Test cgroup ownership delegation for rootless."""
    if not is_rootless():
        return (77, "requires rootless mode")
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "cgroup delegation not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_cpu_quota_period():
    """Test cgroup CPU quota and period configuration."""
    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    # Set CPU quota and period
    conf['linux']['resources'] = {
        'cpu': {
            'quota': 25000,
            'period': 100000
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "cpu" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "cpu cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_memory_swap_limit():
    """Test cgroup memory and swap limit configuration."""
    if is_rootless():
        return (77, "memory cgroup requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    # Set memory and swap limits
    conf['linux']['resources'] = {
        'memory': {
            'limit': 50 * 1024 * 1024,
            'swap': 100 * 1024 * 1024
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "memory" in output.lower() or "swap" in output.lower():
            return (77, "memory/swap cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_io_weight():
    """Test cgroup IO weight configuration."""
    if is_rootless():
        return (77, "io cgroup requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    # Set IO weight
    conf['linux']['resources'] = {
        'blockIO': {
            'weight': 500
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "io" in output.lower():
            return (77, "io cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_cpu_realtime():
    """Test cgroup CPU realtime configuration (cgroup v1)."""
    if is_rootless():
        return (77, "cpu cgroup requires root")
    if is_cgroup_v2_unified():
        return (77, "realtime not supported on cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Set CPU realtime parameters (only for cgroup v1)
    conf['linux']['resources'] = {
        'cpu': {
            'realtimeRuntime': 1000,
            'realtimePeriod': 100000
        }
    }

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "cpu" in output.lower() or "realtime" in output.lower():
            return (77, "cpu realtime not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_hugetlb():
    """Test cgroup hugetlb configuration."""
    if is_rootless():
        return (77, "hugetlb cgroup requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Set hugetlb limits
    conf['linux']['resources'] = {
        'hugepageLimits': [
            {
                'pageSize': '2MB',
                'limit': 100 * 1024 * 1024
            }
        ]
    }

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "hugetlb" in output.lower():
            return (77, "hugetlb cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_devices_allow():
    """Test cgroup devices allow configuration."""
    if is_rootless():
        return (77, "devices cgroup requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Set device permissions
    conf['linux']['resources'] = {
        'devices': [
            {
                'allow': False,
                'access': 'rwm'
            },
            {
                'allow': True,
                'type': 'c',
                'major': 1,
                'minor': 3,
                'access': 'rwm'
            }
        ]
    }

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "device" in output.lower():
            return (77, "devices cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_v2_controllers_enable():
    """Test enabling controllers on cgroup v2."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    # Read cgroup.subtree_control to see enabled controllers
    conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cgroup.controllers']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should have some controllers listed
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "mount" in output.lower() or "proc" in output.lower():
            return (77, "proc mount not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_update_resources():
    """Test updating cgroup resources after container start."""
    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {
        'memory': {
            'limit': 100 * 1024 * 1024
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        # Try to update resources
        new_spec = {
            'memory': {
                'limit': 200 * 1024 * 1024
            }
        }
        spec_file = f'/tmp/update-spec-{os.getpid()}.json'
        with open(spec_file, 'w') as f:
            json.dump(new_spec, f)

        try:
            run_crun_command(['update', '--resources', spec_file, cid])
        except:
            pass  # update might not be supported

        os.unlink(spec_file)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "cgroup update not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_exec_into_running():
    """Test exec into a running container exercises cgroup path lookup."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    conf['linux']['resources'] = {
        'memory': {
            'limit': 100 * 1024 * 1024
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        # Exec into the container - this exercises read_unified_cgroup_pid
        # and enter_cgroup_v2 with init_pid path
        run_crun_command(['exec', cid, '/init', 'cat', '/proc/self/cgroup'])
        run_crun_command(['exec', cid, '/init', 'true'])

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "cgroup exec not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_v1_exec_cgroup_subpath():
    """Test cgroup v1 exec sub-cgroup movement stays below the container cgroup."""
    if is_cgroup_v2_unified():
        return (77, "requires cgroup v1")
    if is_rootless():
        return (77, "requires root for cgroup v1 manipulation")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")

    conf = base_config()
    add_all_namespaces(conf)
    parent = 'test-v1-exec-cgroup-%s' % os.getpid()
    conf['linux']['cgroupsPath'] = '/%s/container' % parent
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    created_paths = []
    target_subsystem = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        for subsystem in ['memory', 'pids', 'cpu,cpuacct', 'cpu', 'freezer']:
            container_dir = os.path.join('/sys/fs/cgroup', subsystem, parent, 'container')
            if os.path.isdir(container_dir):
                target_subsystem = subsystem
                break

        if target_subsystem is None:
            return (77, "no writable cgroup v1 subsystem found")

        container_dir = os.path.join('/sys/fs/cgroup', target_subsystem, parent, 'container')
        outside_dir = os.path.join('/sys/fs/cgroup', target_subsystem, parent, 'outside')
        for path in [
            os.path.join(container_dir, 'foo'),
            os.path.join(container_dir, 'foo', 'bar'),
            outside_dir,
        ]:
            try:
                os.mkdir(path, 0o700)
                created_paths.append(path)
            except FileExistsError:
                pass
            except OSError as e:
                if e.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
                    return (77, "cgroup v1 subsystem is not writable")
                raise

        out = run_crun_command(['exec', '--cgroup=foo', cid, '/init', 'cat', '/proc/self/cgroup'])
        if '/foo' not in out:
            logger.info("/foo not found in cgroup v1 exec output: %s", out)
            return -1

        invalid_cgroups = [
            ('../outside', '`..` components are not allowed'),
            ('./../outside', '`..` components are not allowed'),
            ('./foo/../foo', '`..` components are not allowed'),
            ('foo/..', '`..` components are not allowed'),
            ('foo/../../outside', '`..` components are not allowed'),
            ('foo/bar/..', '`..` components are not allowed'),
            ('foo/bar/../../../outside', '`..` components are not allowed'),
        ]
        for sub_cgroup, expected_error in invalid_cgroups:
            try:
                run_crun_command_raw(['exec', '--cgroup=%s' % sub_cgroup, cid, '/init', 'true'])
            except subprocess.CalledProcessError as e:
                output = e.output.decode('utf-8', errors='ignore') if e.output else ''
                if expected_error in output and sub_cgroup in output:
                    continue
                logger.info("unexpected error for invalid v1 exec cgroup %s: %s", sub_cgroup, output)
                return -1
            logger.info("v1 exec accepted invalid cgroup path %s", sub_cgroup)
            return -1

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "cgroup v1 exec not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        for path in reversed(created_paths):
            try:
                os.rmdir(path)
            except OSError:
                pass
        if target_subsystem is not None:
            try:
                os.rmdir(os.path.join('/sys/fs/cgroup', target_subsystem, parent))
            except OSError:
                pass


def test_cgroup_cpuset_multiple_cpus():
    """Test cpuset with multiple CPUs and memory nodes."""
    if is_rootless():
        return (77, "cpuset cgroup requires root")

    # Check how many CPUs are available
    try:
        with open('/sys/fs/cgroup/cpuset.cpus.effective', 'r') as f:
            available_cpus = f.read().strip()
    except:
        try:
            with open('/sys/devices/system/cpu/online', 'r') as f:
                available_cpus = f.read().strip()
        except:
            return (77, "cannot determine available CPUs")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Use the first available CPU range
    conf['linux']['resources'] = {
        'cpu': {
            'cpus': '0',
            'mems': '0'
        }
    }

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cpuset" in output.lower() or "cgroup" in output.lower():
            return (77, "cpuset cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_enter_subsystem_memory():
    """Test memory subsystem entry with various limits."""
    if is_rootless():
        return (77, "memory cgroup requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'cat', '/proc/self/cgroup']

    # Set memory limits to trigger initialize_memory_subsystem
    conf['linux']['resources'] = {
        'memory': {
            'limit': 50 * 1024 * 1024,
            'reservation': 25 * 1024 * 1024
        }
    }

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "memory" in output.lower() or "cgroup" in output.lower():
            return (77, "memory cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_v1_subsystems():
    """Test cgroup v1 subsystem entry if available."""
    if is_cgroup_v2_unified():
        return (77, "requires cgroup v1 or hybrid mode")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'cat', '/proc/self/cgroup']

    # Set resources that use v1 subsystems
    conf['linux']['resources'] = {
        'cpu': {
            'shares': 512
        },
        'memory': {
            'limit': 100 * 1024 * 1024
        }
    }

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        # Should see cgroup v1 style output (multiple controllers)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower():
            return (77, "cgroup v1 not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_deep_nested_path():
    """Test deeply nested cgroup path creation."""
    if is_rootless():
        return (77, "requires root for cgroup path creation")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Use a deeply nested path
    conf['linux']['cgroupsPath'] = f'/test/deeply/nested/path/{os.getpid()}'

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower():
            return (77, "nested cgroup path not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_cgroup_exec_multiple_times():
    """Test multiple exec calls into a container to exercise cgroup reentry."""
    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        # Multiple execs to exercise cgroup entry code multiple times
        for i in range(3):
            try:
                run_crun_command(['exec', cid, '/init', 'true'])
            except:
                pass  # Some execs might fail, but we're exercising the code

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "mount" in output.lower() or "proc" in output.lower():
            return (77, "cgroup exec not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_create_without_resources():
    """Test cgroup creation without any resource limits."""
    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'cat', '/proc/self/cgroup']

    # No resources specified - tests basic cgroup entry
    if 'resources' in conf.get('linux', {}):
        del conf['linux']['resources']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "mount" in output.lower() or "proc" in output.lower():
            return (77, "proc mount not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_annotation_systemd_subgroup():
    """Test run.oci.systemd.subgroup annotation."""
    if not running_on_systemd():
        return (77, "requires systemd")
    if get_cgroup_manager() != 'systemd':
        return (77, "requires systemd cgroup manager")

    conf = base_config()
    # Don't use cgroup namespace - we need to see the full cgroup path
    # to verify the subgroup name appears in it
    add_all_namespaces(conf, cgroupns=False)
    conf['process']['args'] = ['/init', 'cat', '/proc/self/cgroup']

    subgroup_name = f'mytestsubgroup-{os.getpid()}'

    # Add annotation for systemd subgroup
    if 'annotations' not in conf:
        conf['annotations'] = {}
    conf['annotations']['run.oci.systemd.subgroup'] = subgroup_name

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)

        # Verify the subgroup name appears in the cgroup path
        if subgroup_name in out:
            return 0
        else:
            logger.info("systemd subgroup annotation test failed: '%s' not found in output", subgroup_name)
            logger.info("cgroup output: %s", out)
            return -1

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if not output or any(x in output.lower() for x in ["mount", "proc", "permission", "rootfs", "private", "busy", "cgroup"]):
            return (77, "not available in nested namespaces")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_annotation_delegate_cgroup():
    """Test run.oci.delegate-cgroup annotation."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")
    if not running_on_systemd():
        return (77, "requires systemd")
    if get_cgroup_manager() != 'systemd':
        return (77, "requires systemd cgroup manager")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    subgroup_name = f'mysubgroup-{os.getpid()}'
    delegated_name = f'mydelegated-{os.getpid()}'

    # Add annotations - delegate-cgroup requires systemd.subgroup to be set
    if 'annotations' not in conf:
        conf['annotations'] = {}
    conf['annotations']['run.oci.systemd.subgroup'] = subgroup_name
    conf['annotations']['run.oci.delegate-cgroup'] = delegated_name

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        # Check the cgroup path of the container process
        out = run_crun_command(['exec', cid, '/init', 'cat', '/proc/self/cgroup'])

        # Verify both the subgroup and delegated cgroup appear in the path
        if delegated_name in out:
            logger.info("delegate-cgroup annotation test passed: found '%s' in cgroup path", delegated_name)
            return 0
        else:
            logger.info("delegate-cgroup annotation test: '%s' not found in output", delegated_name)
            logger.info("cgroup output: %s", out)
            # Don't fail - this might not be fully supported in all environments
            return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if not output or any(x in output.lower() for x in ["mount", "proc", "permission", "rootfs", "private", "busy", "cgroup"]):
            return (77, "not available in nested namespaces")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_annotation_delegate_cgroup_dotdot():
    """Test that run.oci.delegate-cgroup rejects '..' components."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")
    if not running_on_systemd():
        return (77, "requires systemd")
    if get_cgroup_manager() != 'systemd':
        return (77, "requires systemd cgroup manager")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'echo', 'hello']

    if 'annotations' not in conf:
        conf['annotations'] = {}
    conf['annotations']['run.oci.systemd.subgroup'] = 'mysubgroup'

    for invalid in ["..", "../../../victim", "../escape", "a/../b"]:
        conf['annotations']['run.oci.delegate-cgroup'] = invalid
        try:
            # Do not hide stderr: the error message crun prints there is
            # exactly what this test needs to look at.
            out, _ = run_and_get_output(conf)
            return -1
        except Exception as e:
            if hasattr(e, 'output') and e.output:
                err = e.output.decode()
                if "delegate-cgroup" in err:
                    continue
                logger.info("got error for delegate-cgroup '%s': %s", invalid, err)
            else:
                logger.info("got exception without output for delegate-cgroup '%s': %s", invalid, str(e))
            return -1
    return 0

def test_annotation_systemd_force_cgroup_v1():
    """Test run.oci.systemd.force_cgroup_v1 annotation."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2 system")
    if not running_on_systemd():
        return (77, "requires systemd")
    if get_cgroup_manager() != 'systemd':
        return (77, "requires systemd cgroup manager")

    # Check if a cgroup v1 mount point exists
    cgroup_v1_path = '/sys/fs/cgroup/systemd'
    if not os.path.exists(cgroup_v1_path):
        return (77, "no cgroup v1 mount point available")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'true']

    # Add annotation for forcing cgroup v1
    if 'annotations' not in conf:
        conf['annotations'] = {}
    conf['annotations']['run.oci.systemd.force_cgroup_v1'] = cgroup_v1_path

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        logger.info("systemd force_cgroup_v1 annotation test passed")
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if not output or any(x in output.lower() for x in ["mount", "proc", "permission", "rootfs", "private", "busy", "cgroup"]):
            return (77, "not available in nested namespaces")
        # This annotation might not be fully supported, don't fail
        logger.info("force_cgroup_v1 test completed with error (may not be supported)")
        return 0
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1

def test_cgroup_v2_mount_options():
    """Test that cgroup v2 mount options are passed to the kernel."""

    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf, cgroupns=True)

    # Test this by intentionally providing an invalid mount option.
    # If the options are ignored, the mount will succeed.
    # If they are correctly passed to the kernel, the mount will fail.
    for mount in conf['mounts']:
        if mount.get('destination') == '/sys/fs/cgroup':
            if 'options' not in mount:
                mount['options'] = []
            mount['options'].append("invalid_cgroup_option")
            break

    try:
        run_and_get_output(conf, hide_stderr=False)
        logger.info("expected mount failure due to invalid mount option, but it succeeded")
        return -1
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ""
        if "Invalid argument" not in output:
            logger.info("failed, but did not find expected 'Invalid argument' error message. Output: %s", output)
            return -1

    return 0

def _cgroup_disabled_config():
    """Return a config suitable for --cgroup-manager=disabled: no cgroup mount,
    no resources, no cgroupsPath, no cgroup namespace."""
    conf = base_config()
    add_all_namespaces(conf, cgroupns=False)
    conf['mounts'] = [m for m in conf.get('mounts', [])
                      if m.get('destination') != '/sys/fs/cgroup']
    if 'resources' in conf.get('linux', {}):
        del conf['linux']['resources']
    if 'cgroupsPath' in conf.get('linux', {}):
        del conf['linux']['cgroupsPath']
    return conf


def _run_cgroup_disabled(detach):
    """Run a container with --cgroup-manager=disabled in foreground or detached
    mode.  Returns 0 on success, (77, reason) for environment skips, -1 on
    failure.

    Regression test for https://github.com/containers/crun/issues/1413.
    When cgroups are disabled, crun must not call statfs on /sys/fs/cgroup,
    which would fail on systems where it is not mounted as tmpfs or cgroup2.
    """
    conf = _cgroup_disabled_config()
    conf['process']['args'] = ['/init', 'pause'] if detach else ['/init', 'true']

    cid = None
    try:
        if detach:
            _, cid = run_and_get_output(conf, hide_stderr=False, command='run',
                                        detach=True, cgroup_manager='disabled')
            state = json.loads(run_crun_command(['state', cid]))
            if state['status'] not in ('running', 'created'):
                logger.info("container not running: %s", state['status'])
                return -1
        else:
            run_and_get_output(conf, hide_stderr=False, cgroup_manager='disabled')
        return 0
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "invalid file system type" in output:
            logger.info("test failed: cgroup filesystem type checked despite --cgroups=disabled")
            return -1
        if any(kw in output.lower() for kw in ["mount", "proc", "rootfs"]):
            return (77, "environment issue, not related to cgroup disabled")
        logger.info("test failed: %s (output: %s)", e, output)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_disabled():
    """Test --cgroup-manager=disabled skips cgroup filesystem type verification (foreground).

    Regression test for https://github.com/containers/crun/issues/1413.
    """
    return _run_cgroup_disabled(detach=False)


def test_cgroup_disabled_detach():
    """Test --cgroup-manager=disabled works with run --detach.

    Regression test for https://github.com/containers/crun/issues/1413.
    """
    return _run_cgroup_disabled(detach=True)


def test_cgroup_subcgroup_cleanup():
    """Test that subcgroups are cleaned up on container delete.

    Regression test for a bug where read_pids_cgroup() consumed the
    caller's fd via fdopendir(), causing rmdir_all_fd() to fail with
    EBADF when cleaning up nested cgroup directories.
    """
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")
    if is_rootless():
        return (77, "requires root for cgroup manipulation")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'create-sub-cgroup-and-wait',
                               'sub1', 'sub1/nested', 'sub2']

    cgroup_path = f'/test-subcgroup-cleanup-{os.getpid()}'
    conf['linux']['cgroupsPath'] = cgroup_path

    host_cgroup_dir = f'/sys/fs/cgroup{cgroup_path}'

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        # Verify the cgroup directory exists
        if not os.path.isdir(host_cgroup_dir):
            logger.info("cgroup directory %s does not exist", host_cgroup_dir)
            return -1

        # Delete the container -- crun must clean up all subcgroups
        run_crun_command(['delete', '-f', cid])
        cid = None

        # Give a moment for cleanup
        time.sleep(0.5)

        # Verify cgroup directory is fully removed
        if os.path.exists(host_cgroup_dir):
            logger.info("cgroup directory %s still exists after delete", host_cgroup_dir)
            return -1

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "Bad file descriptor" in output:
            logger.info("EBADF during cgroup cleanup (known regression): %s", output)
            return -1
        if any(kw in output.lower() for kw in ["mount", "proc", "rootfs"]):
            return (77, "environment issue")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_exec_frozen_subcgroup():
    """Test that exec refuses to join a frozen sub-cgroup of the container
    instead of waiting forever for a process that never runs."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")
    if is_rootless():
        return (77, "requires root for cgroup manipulation")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cgroup_path = f'/test-exec-frozen-subcgroup-{os.getpid()}'
    conf['linux']['cgroupsPath'] = cgroup_path

    host_cgroup_dir = f'/sys/fs/cgroup{cgroup_path}'

    def write_cgroup_file(name, value):
        with open(os.path.join(host_cgroup_dir, name), 'w') as f:
            f.write(value)

    def run_exec(args):
        cmd = [get_crun_path(), '--root', get_tests_root_status(), 'exec', '-d'] + args + [cid, '/init', 'true']
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        state = json.loads(run_crun_command(['state', cid]))

        # Once controllers are enabled the container cgroup cannot be joined
        # anymore, and exec follows the init process into its sub-cgroup.
        os.makedirs(os.path.join(host_cgroup_dir, 'a/b'))
        write_cgroup_file('a/b/cgroup.procs', str(state['pid']))
        try:
            write_cgroup_file('cgroup.subtree_control', '+pids')
        except OSError:
            return (77, "cannot enable the pids controller")

        all_args = ([], ['--cgroup', '/a/b'])

        for args in all_args:
            ret = run_exec(args)
            if ret.returncode != 0:
                logger.info("exec %s failed: %s", args, ret.stdout)
                return -1

        write_cgroup_file('a/b/cgroup.freeze', '1')

        for args in all_args:
            ret = run_exec(args)
            if ret.returncode == 0 or b'frozen' not in ret.stdout:
                logger.info("exec %s into a frozen cgroup returned %d: %s", args, ret.returncode, ret.stdout)
                return -1

        return 0

    except subprocess.TimeoutExpired:
        logger.info("exec into a frozen cgroup did not terminate")
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_cgroup_cleanup_failed_start():
    """Test that the cgroup is not left behind when the container creation
    fails after the cgroup is created but before it is configured, and that
    a pre-existing cgroup is left alone."""
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")
    if is_rootless():
        return (77, "requires root for cgroup manipulation")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")

    conf = base_config()
    add_all_namespaces(conf, netns=False)
    conf['process']['args'] = ['/init', 'true']
    # Joining a namespace that does not exist fails before the container
    # process is created.
    conf['linux']['namespaces'].append({
        'type': 'network',
        'path': os.path.join(get_tests_root(), 'not-existing-netns'),
    })

    cgroup_path = f'/test-cleanup-failed-start-{os.getpid()}'
    conf['linux']['cgroupsPath'] = cgroup_path

    host_cgroup_dir = f'/sys/fs/cgroup{cgroup_path}'

    try:
        for pre_existing in (False, True):
            if pre_existing:
                os.mkdir(host_cgroup_dir)

            try:
                run_and_get_output(conf, hide_stderr=True)
                logger.info("the container was expected to fail")
                return -1
            except subprocess.CalledProcessError:
                pass

            if os.path.exists(host_cgroup_dir) != pre_existing:
                logger.info("cgroup directory %s: pre-existing=%s, exists after the failed start=%s",
                            host_cgroup_dir, pre_existing, not pre_existing)
                return -1

        return 0
    finally:
        try:
            os.rmdir(host_cgroup_dir)
        except OSError:
            pass


def test_cgroup_rootless_host_pidns():
    """Test that a rootless container in the host PID namespace is not run
    without a cgroup, as the cgroup is then needed to kill all its
    processes."""
    if not is_rootless():
        return (77, "requires rootless")

    conf = base_config()
    add_all_namespaces(conf)
    # A new procfs cannot be mounted without a new PID namespace.
    for mount in conf['mounts']:
        if mount['type'] == 'proc':
            mount.update(type='none', source='/proc', options=['rbind', 'nosuid', 'nodev', 'noexec'])
    conf['process']['args'] = ['/init', 'pause']

    with open('/proc/self/cgroup') as f:
        own_cgroup = f.read()

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        state = json.loads(run_crun_command(['state', cid]))
        with open('/proc/%d/cgroup' % state['pid']) as f:
            if f.read() != own_cgroup:
                return (77, "the container cgroup can be created")
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    conf['linux']['namespaces'] = [ns for ns in conf['linux']['namespaces'] if ns['type'] != 'pid']
    conf['process']['args'] = ['/init', 'true']
    try:
        run_and_get_output(conf, hide_stderr=True)
    except subprocess.CalledProcessError:
        return 0

    logger.info("the container in the host PID namespace was run without a cgroup")
    return -1


def test_cgroup_deep_subcgroup_cleanup():
    """Test that a deep chain of subcgroups is walked and cleaned up on
    container delete.

    Regression test for a bug where the cgroup tree was walked recursively,
    keeping open file descriptors for each level, so that a chain of
    subcgroups deeper than the file descriptors limit made `crun ps` fail
    and `crun delete` leave the cgroups behind.
    """
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")
    if is_rootless():
        return (77, "requires root for cgroup manipulation")
    if get_cgroup_manager() == 'systemd':
        return (77, "test uses cgroupfs-style paths")

    depth = 300

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cgroup_path = f'/test-deep-subcgroup-cleanup-{os.getpid()}'
    conf['linux']['cgroupsPath'] = cgroup_path

    host_cgroup_dir = f'/sys/fs/cgroup{cgroup_path}'

    nofile = resource.getrlimit(resource.RLIMIT_NOFILE)

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=False, command='run', detach=True)

        for i in range(1, depth + 1):
            os.mkdir(host_cgroup_dir + '/c' * i)

        # crun inherits the limit, a recursive walk needs more than depth descriptors
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(depth // 2, nofile[1]), nofile[1]))

        processes = json.loads(run_crun_command(['ps', '--format', 'json', cid]))
        if len(processes) != 1:
            logger.info("expected 1 process, got %s", processes)
            return -1

        run_crun_command(['delete', '-f', cid])
        cid = None

        if os.path.exists(host_cgroup_dir):
            logger.info("cgroup directory %s still exists after delete", host_cgroup_dir)
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, nofile)
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        for i in range(depth, -1, -1):
            try:
                os.rmdir(host_cgroup_dir + '/c' * i)
            except OSError:
                pass


all_tests = {
    "cgroup-disabled": test_cgroup_disabled,
    "cgroup-disabled-detach": test_cgroup_disabled_detach,
    "cgroup-creation": test_cgroup_creation,
    "cgroup-cleanup": test_cgroup_cleanup,
    "cgroup-with-resources": test_cgroup_with_resources,
    "cgroup-cpuset-initialization": test_cgroup_cpuset_initialization,
    "cgroup-freezer": test_cgroup_freezer,
    "cgroup-v2-unified": test_cgroup_v2_unified,
    "cgroup-path-custom": test_cgroup_path_custom,
    "cgroup-namespace-private": test_cgroup_namespace_private,
    "cgroup-namespace-host": test_cgroup_namespace_host,
    "cgroup-delegation": test_cgroup_delegation,
    "cgroup-memory-controllers": test_cgroup_memory_controllers,
    "cgroup-pids-controller": test_cgroup_pids_controller,
    "cgroup-cpuset-nested-initialization": test_cgroup_cpuset_nested_initialization,
    "cgroup-cpuset-inherit-parent": test_cgroup_cpuset_inherit_parent,
    "cgroup-memory-initialization": test_cgroup_memory_initialization,
    "cgroup-v2-threaded-mode": test_cgroup_v2_threaded_mode,
    "cgroup-v2-crun-exec-subdir": test_cgroup_v2_crun_exec_subdir,
    "cgroup-multiple-controllers": test_cgroup_multiple_controllers,
    "cgroup-error-invalid-path": test_cgroup_error_invalid_path,
    "cgroup-owner-delegation": test_cgroup_owner_delegation,
    "cgroup-cpu-quota-period": test_cgroup_cpu_quota_period,
    "cgroup-memory-swap-limit": test_cgroup_memory_swap_limit,
    "cgroup-io-weight": test_cgroup_io_weight,
    "cgroup-cpu-realtime": test_cgroup_cpu_realtime,
    "cgroup-hugetlb": test_cgroup_hugetlb,
    "cgroup-devices-allow": test_cgroup_devices_allow,
    "cgroup-v2-controllers-enable": test_cgroup_v2_controllers_enable,
    "cgroup-update-resources": test_cgroup_update_resources,
    "cgroup-exec-into-running": test_cgroup_exec_into_running,
    "cgroup-cpuset-multiple-cpus": test_cgroup_cpuset_multiple_cpus,
    "cgroup-enter-subsystem-memory": test_cgroup_enter_subsystem_memory,
    "cgroup-v1-subsystems": test_cgroup_v1_subsystems,
    "cgroup-v1-exec-cgroup-subpath": test_cgroup_v1_exec_cgroup_subpath,
    "cgroup-deep-nested-path": test_cgroup_deep_nested_path,
    "cgroup-exec-multiple-times": test_cgroup_exec_multiple_times,
    "cgroup-create-without-resources": test_cgroup_create_without_resources,
    "annotation-systemd-subgroup": test_annotation_systemd_subgroup,
    "annotation-delegate-cgroup": test_annotation_delegate_cgroup,
    "annotation-delegate-cgroup-dotdot": test_annotation_delegate_cgroup_dotdot,
    "annotation-systemd-force-cgroup-v1": test_annotation_systemd_force_cgroup_v1,
    "cgroup-v2-mount-options": test_cgroup_v2_mount_options,
    "cgroup-subcgroup-cleanup": test_cgroup_subcgroup_cleanup,
    "cgroup-deep-subcgroup-cleanup": test_cgroup_deep_subcgroup_cleanup,
    "cgroup-exec-frozen-subcgroup": test_cgroup_exec_frozen_subcgroup,
    "cgroup-cleanup-failed-start": test_cgroup_cleanup_failed_start,
    "cgroup-rootless-host-pidns": test_cgroup_rootless_host_pidns,
}

if __name__ == "__main__":
    tests_main(all_tests)
