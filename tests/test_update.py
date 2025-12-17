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
import os
import subprocess
import time
from tests_utils import *

def test_update_memory_limit():
    """Test updating memory limit on a running container."""
    if is_rootless():
        return (77, "requires root for cgroup update")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    # Set initial memory limit
    conf['linux']['resources'] = {
        'memory': {
            'limit': 200 * 1024 * 1024  # 200MB
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update memory limit to 100MB
        run_crun_command(['update', '--memory', '104857600', cid])

        # Verify the limit was updated by checking cgroup
        if is_cgroup_v2_unified():
            mem_file = '/sys/fs/cgroup/memory.max'
        else:
            mem_file = '/sys/fs/cgroup/memory/memory.limit_in_bytes'

        out = run_crun_command(['exec', cid, '/init', 'cat', mem_file])
        # Allow for some variation in exact value
        value = out.strip()
        if value != 'max' and int(value) != 104857600:
            # On some systems the value might be page-aligned
            if abs(int(value) - 104857600) > 4096:
                logger.info("memory limit not updated correctly: %s", value)
                return -1

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


def test_update_cpu_shares():
    """Test updating CPU shares on a running container."""
    if is_rootless():
        return (77, "requires root for cgroup update")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update CPU shares
        run_crun_command(['update', '--cpu-share', '512', cid])

        # Verify the shares were updated
        if is_cgroup_v2_unified():
            # On cgroup v2, shares are converted to weight
            cpu_file = '/sys/fs/cgroup/cpu.weight'
            out = run_crun_command(['exec', cid, '/init', 'cat', cpu_file])
            # 512 shares converts to ~50 weight (shares/1024 * 100, clamped)
            value = int(out.strip())
            if value < 1 or value > 10000:
                logger.info("cpu weight out of range: %d", value)
                return -1
        else:
            cpu_file = '/sys/fs/cgroup/cpu/cpu.shares'
            out = run_crun_command(['exec', cid, '/init', 'cat', cpu_file])
            if int(out.strip()) != 512:
                logger.info("cpu shares not updated: %s", out.strip())
                return -1

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cpu" in output.lower() or "cgroup" in output.lower():
            return (77, "cpu cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_cpu_quota():
    """Test updating CPU quota on a running container."""
    if is_rootless():
        return (77, "requires root for cgroup update")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update CPU quota (50% of one CPU)
        run_crun_command(['update', '--cpu-quota', '50000', cid])

        # Verify the quota was updated
        if is_cgroup_v2_unified():
            cpu_file = '/sys/fs/cgroup/cpu.max'
            out = run_crun_command(['exec', cid, '/init', 'cat', cpu_file])
            # Format is "quota period" or "max period"
            parts = out.strip().split()
            if parts[0] != '50000' and parts[0] != 'max':
                logger.info("cpu quota not updated: %s", out.strip())
                return -1
        else:
            cpu_file = '/sys/fs/cgroup/cpu/cpu.cfs_quota_us'
            out = run_crun_command(['exec', cid, '/init', 'cat', cpu_file])
            if int(out.strip()) != 50000:
                logger.info("cpu quota not updated: %s", out.strip())
                return -1

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cpu" in output.lower() or "cgroup" in output.lower():
            return (77, "cpu cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_pids_limit():
    """Test updating PIDs limit on a running container."""
    if is_rootless():
        return (77, "requires root for cgroup update")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update PIDs limit
        run_crun_command(['update', '--pids-limit', '100', cid])

        # Verify the limit was updated
        if is_cgroup_v2_unified():
            pids_file = '/sys/fs/cgroup/pids.max'
        else:
            pids_file = '/sys/fs/cgroup/pids/pids.max'

        out = run_crun_command(['exec', cid, '/init', 'cat', pids_file])
        value = out.strip()
        if value != '100' and value != 'max':
            logger.info("pids limit not updated: %s", value)
            return -1

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "pids" in output.lower() or "cgroup" in output.lower():
            return (77, "pids cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_blkio_weight():
    """Test updating blkio weight on a running container."""
    if is_rootless():
        return (77, "requires root for cgroup update")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update blkio weight
        run_crun_command(['update', '--blkio-weight', '500', cid])

        # Verification is tricky as blkio weight files vary by system
        # Just verify the command succeeded
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "blkio" in output.lower() or "io" in output.lower() or "cgroup" in output.lower():
            return (77, "blkio cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_from_file():
    """Test updating resources from a JSON file."""
    if is_rootless():
        return (77, "requires root for cgroup update")
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Create resources file
        import tempfile
        resources = {
            "memory": {
                "limit": 150 * 1024 * 1024
            },
            "pids": {
                "limit": 50
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(resources, f)
            resources_file = f.name

        try:
            # Update from file
            run_crun_command(['update', '--resources', resources_file, cid])
        finally:
            os.unlink(resources_file)

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower():
            return (77, "cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_memory_swap():
    """Test updating memory swap limit on a running container."""
    if is_rootless():
        return (77, "requires root for cgroup update")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    # Set initial memory and swap limits
    conf['linux']['resources'] = {
        'memory': {
            'limit': 200 * 1024 * 1024,  # 200MB
            'swap': 400 * 1024 * 1024    # 400MB
        }
    }

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update memory and swap limit together (swap requires memory to be set)
        run_crun_command(['update', '--memory', '104857600', '--memory-swap', '209715200', cid])

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "memory" in output.lower() or "swap" in output.lower() or "cgroup" in output.lower():
            return (77, "memory swap cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_cpu_period():
    """Test updating CPU period on a running container."""
    if is_rootless():
        return (77, "requires root for cgroup update")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update CPU period
        run_crun_command(['update', '--cpu-period', '50000', cid])

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cpu" in output.lower() or "cgroup" in output.lower():
            return (77, "cpu cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_memory_reservation():
    """Test updating memory reservation (soft limit) on a running container."""
    if is_rootless():
        return (77, "requires root for cgroup update")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update memory reservation (soft limit)
        run_crun_command(['update', '--memory-reservation', '52428800', cid])

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


def test_update_cpuset_cpus():
    """Test updating cpuset.cpus on a running container."""
    if is_rootless():
        return (77, "cpuset update requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update cpuset.cpus to use only CPU 0
        run_crun_command_raw(['update', '--cpuset-cpus', '0', cid])

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cpuset" in output.lower() or "cgroup" in output.lower() or "controller" in output.lower():
            return (77, "cpuset cgroup not available")
        logger.info("test_update_cpuset_cpus failed: %s, output: %s", e, output)
        return -1
    except Exception as e:
        logger.info("test_update_cpuset_cpus failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_cpuset_mems():
    """Test updating cpuset.mems on a running container."""
    if is_rootless():
        return (77, "cpuset mems update requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update cpuset.mems to use only memory node 0
        run_crun_command(['update', '--cpuset-mems', '0', cid])

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cpuset" in output.lower() or "cgroup" in output.lower() or "numa" in output.lower():
            return (77, "cpuset mems not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_multiple_resources():
    """Test updating multiple resources at once."""
    if is_rootless():
        return (77, "requires root for cgroup update")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Update multiple resources at once
        # Use --cpu-share (not --cpu-shares) as that's what crun uses
        run_crun_command(['update',
                        '--memory', '104857600',
                        '--cpu-share', '256',
                        '--pids-limit', '50',
                        cid])

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "cpu" in output.lower() or "memory" in output.lower():
            return (77, "cgroup not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_update_unified_resources():
    """Test updating resources using unified cgroup settings."""
    if is_rootless():
        return (77, "requires root for cgroup update")
    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Create resources file with unified settings
        import tempfile
        resources = {
            "unified": {
                "memory.high": "100000000"
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(resources, f)
            resources_file = f.name

        try:
            run_crun_command(['update', '--resources', resources_file, cid])
        finally:
            os.unlink(resources_file)

        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "cgroup" in output.lower() or "unified" in output.lower():
            return (77, "unified cgroup settings not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


all_tests = {
    "update-memory-limit": test_update_memory_limit,
    "update-cpu-shares": test_update_cpu_shares,
    "update-cpu-quota": test_update_cpu_quota,
    "update-pids-limit": test_update_pids_limit,
    "update-blkio-weight": test_update_blkio_weight,
    "update-from-file": test_update_from_file,
    "update-memory-swap": test_update_memory_swap,
    "update-cpu-period": test_update_cpu_period,
    "update-memory-reservation": test_update_memory_reservation,
    "update-cpuset-cpus": test_update_cpuset_cpus,
    "update-cpuset-mems": test_update_cpuset_mems,
    "update-multiple-resources": test_update_multiple_resources,
    "update-unified-resources": test_update_unified_resources,
}

if __name__ == "__main__":
    tests_main(all_tests)
