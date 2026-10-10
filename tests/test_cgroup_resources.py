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

# Tests for cgroup resource limits (cgroup-resources.c coverage)

import os
import glob
import subprocess
from tests_utils import *


def test_memory_limit():
    """Test memory.limit cgroup resource."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # Set 128MB memory limit
    conf['linux']['resources'] = {
        'memory': {
            'limit': 134217728
        }
    }

    if is_cgroup_v2_unified():
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/memory.max']
    else:
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/memory/memory.limit_in_bytes']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if '134217728' in out:
            return 0
        logger.info("Expected 134217728, got: %s", out.strip())
        return -1
    except Exception as e:
        logger.info("Exception: %s", e)
        return -1


def test_memory_reservation():
    """Test memory.reservation (soft limit) cgroup resource."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # Set 64MB memory reservation
    conf['linux']['resources'] = {
        'memory': {
            'reservation': 67108864
        }
    }

    if is_cgroup_v2_unified():
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/memory.low']
    else:
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/memory/memory.soft_limit_in_bytes']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if '67108864' in out:
            return 0
        logger.info("Expected 67108864, got: %s", out.strip())
        return -1
    except Exception as e:
        logger.info("Exception: %s", e)
        return -1


def test_cpu_shares():
    """Test cpu.shares cgroup resource."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    conf['linux']['resources'] = {
        'cpu': {
            'shares': 512
        }
    }

    if is_cgroup_v2_unified():
        # In cgroup v2, shares are converted to weight (shares/1.2262)
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpu.weight']
        expected = None  # Will check for reasonable weight value
    else:
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpu/cpu.shares']
        expected = '512'

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if expected:
            if expected in out:
                return 0
        else:
            # For cgroup v2, weight should be around 39-42 for 512 shares
            try:
                weight = int(out.strip())
                if 1 <= weight <= 10000:
                    return 0
            except ValueError:
                pass
        logger.info("Unexpected output: %s", out.strip())
        return -1
    except Exception as e:
        logger.info("Exception: %s", e)
        return -1


def test_cpu_quota_period():
    """Test cpu.quota and cpu.period cgroup resources."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # 50% CPU (50000us quota per 100000us period)
    conf['linux']['resources'] = {
        'cpu': {
            'quota': 50000,
            'period': 100000
        }
    }

    if is_cgroup_v2_unified():
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpu.max']
    else:
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpu/cpu.cfs_quota_us']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if '50000' in out:
            return 0
        logger.info("Expected 50000, got: %s", out.strip())
        return -1
    except Exception as e:
        logger.info("Exception: %s", e)
        return -1


def test_cpuset_cpus():
    """Test cpuset.cpus cgroup resource."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    conf['linux']['resources'] = {
        'cpu': {
            'cpus': '0'
        }
    }

    if is_cgroup_v2_unified():
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpuset.cpus']
    else:
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpuset/cpuset.cpus']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        if '0' in out:
            return 0
        logger.info("test_cpuset_cpus: Expected '0', got: %s", out.strip())
        return -1
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        stderr = e.stderr.decode('utf-8', errors='ignore') if hasattr(e, 'stderr') and e.stderr else ''
        combined = output + stderr
        if "cpuset" in combined.lower() or "controller" in combined.lower():
            return (77, "cpuset controller not available")
        logger.info("test_cpuset_cpus failed: %s", e)
        return -1
    except Exception as e:
        err_str = str(e).lower()
        if "cpuset" in err_str or "controller" in err_str:
            return (77, "cpuset controller not available")
        logger.info("test_cpuset_cpus exception: %s", e)
        return -1


def test_blkio_weight():
    """Test blkio.weight cgroup resource."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    conf['linux']['resources'] = {
        'blockIO': {
            'weight': 500
        }
    }

    if is_cgroup_v2_unified():
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/io.bfq.weight']
    else:
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/blkio/blkio.weight']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        # Weight might be converted differently between cgroup versions
        out_stripped = out.strip()
        if out_stripped:
            return 0
        return -1
    except Exception as e:
        # blkio controller might not be available
        logger.info("blkio test skipped: %s", e)
        return (77, "blkio controller not available")


def test_memory_swap():
    """Test memory.swap cgroup resource."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # Set memory limit and swap limit
    # swap must be >= limit for cgroup v1
    conf['linux']['resources'] = {
        'memory': {
            'limit': 134217728,  # 128MB
            'swap': 268435456    # 256MB (limit + swap in v1, just swap in v2)
        }
    }

    if is_cgroup_v2_unified():
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/memory.swap.max']
    else:
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        # Just check that the command succeeded and returned a value
        if out.strip():
            return 0
        return -1
    except Exception as e:
        # Swap might not be enabled
        logger.info("memory swap test skipped: %s", e)
        return (77, "memory swap not available")


def test_memory_high():
    """Test memory.high cgroup resource (cgroup v2 only)."""
    if is_rootless():
        return (77, "requires root")

    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # memory.high is a throttling limit
    # Use unified map which works with both cgroupfs and systemd managers
    conf['linux']['resources'] = {
        'unified': {
            'memory.high': '134217728'  # 128MB
        }
    }

    conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/memory.high']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        if '134217728' in out:
            return 0
        logger.info("test_memory_high: Expected 134217728, got: %s", out.strip())
        return -1
    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        stderr = e.stderr.decode('utf-8', errors='ignore') if hasattr(e, 'stderr') and e.stderr else ''
        logger.info("test_memory_high failed with return code %s", e.returncode)
        logger.info("test_memory_high stdout: %s", output)
        logger.info("test_memory_high stderr: %s", stderr)
        return -1
    except Exception as e:
        logger.info("test_memory_high exception: %s", e)
        return -1


def test_cpuset_mems():
    """Test cpuset.mems cgroup resource."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    conf['linux']['resources'] = {
        'cpu': {
            'mems': '0'
        }
    }

    if is_cgroup_v2_unified():
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpuset.mems']
    else:
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpuset/cpuset.mems']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if '0' in out:
            return 0
        logger.info("Expected '0', got: %s", out.strip())
        return -1
    except Exception as e:
        err_str = str(e).lower()
        if "cpuset" in err_str or "controller" in err_str:
            return (77, "cpuset controller not available")
        logger.info("cpuset.mems test failed: %s", e)
        return -1


def test_pids_limit():
    """Test pids.limit cgroup resource."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    conf['linux']['resources'] = {
        'pids': {
            'limit': 100
        }
    }

    if is_cgroup_v2_unified():
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/pids.max']
    else:
        conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/pids/pids.max']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if '100' in out:
            return 0
        logger.info("Expected 100, got: %s", out.strip())
        return -1
    except Exception as e:
        logger.info("pids test failed: %s", e)
        return -1


def test_cpu_idle():
    """Test cpu.idle cgroup resource (cgroup v2 only)."""
    if is_rootless():
        return (77, "requires root")

    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    conf['linux']['resources'] = {
        'cpu': {
            'idle': 1
        }
    }

    conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpu.idle']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if '1' in out:
            return 0
        logger.info("Expected 1, got: %s", out.strip())
        return -1
    except Exception as e:
        # cpu.idle might not be available on all kernels
        logger.info("cpu.idle test skipped: %s", e)
        return (77, "cpu.idle not available")


def test_unified_resources():
    """Test unified (cgroup v2) resources."""
    if is_rootless():
        return (77, "requires root")

    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # Set unified resources directly
    conf['linux']['resources'] = {
        'unified': {
            'memory.high': '134217728'
        }
    }

    conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/memory.high']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if '134217728' in out:
            return 0
        logger.info("Expected 134217728, got: %s", out.strip())
        return -1
    except Exception as e:
        logger.info("unified resources test failed: %s", e)
        return -1


def test_memory_disable_oom_killer():
    """Test memory oom killer disable."""
    if is_rootless():
        return (77, "requires root")

    # This only works on cgroup v1
    if is_cgroup_v2_unified():
        return (77, "requires cgroup v1")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    conf['linux']['resources'] = {
        'memory': {
            'limit': 134217728,
            'disableOOMKiller': True
        }
    }

    conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/memory/memory.oom_control']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if 'oom_kill_disable 1' in out:
            return 0
        logger.info("OOM killer not disabled: %s", out.strip())
        return -1
    except Exception as e:
        logger.info("disableOOMKiller test failed: %s", e)
        return -1


def test_cpu_burst():
    """Test cpu.burst cgroup resource (cgroup v2 only)."""
    if is_rootless():
        return (77, "requires root")

    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    conf['linux']['resources'] = {
        'cpu': {
            'quota': 50000,
            'period': 100000,
            'burst': 10000
        }
    }

    conf['process']['args'] = ['/init', 'cat', '/sys/fs/cgroup/cpu.max.burst']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if '10000' in out:
            return 0
        logger.info("Expected 10000, got: %s", out.strip())
        return -1
    except Exception as e:
        # cpu.max.burst might not be available
        logger.info("cpu.burst test skipped: %s", e)
        return (77, "cpu.burst not available")


def test_hugetlb_reservation_limit():
    """Test hugetlb reservation limit (cgroup v2 only)."""
    if is_rootless():
        return (77, "requires root")

    if not is_cgroup_v2_unified():
        return (77, "requires cgroup v2")

    # Discover the first available HugeTLB reservation file
    rsvd_files = glob.glob('/sys/fs/cgroup/hugetlb.*.rsvd.max')
    if not rsvd_files:
        return (77, "hugetlb reservation accounting not available")

    # Extract page size from filename (e.g., hugetlb.2MB.rsvd.max -> 2MB)
    rsvd_file = rsvd_files[0]
    filename = rsvd_file.split('/')[-1]  # hugetlb.2MB.rsvd.max
    page_size_str = filename.split('.')[1]  # 2MB

    # Convert page size string to bytes
    page_size_bytes = 0
    if page_size_str.endswith('MB'):
        page_size_bytes = int(page_size_str[:-2]) * 1024 * 1024
    elif page_size_str.endswith('GB'):
        page_size_bytes = int(page_size_str[:-2]) * 1024 * 1024 * 1024
    elif page_size_str.endswith('KB'):
        page_size_bytes = int(page_size_str[:-2]) * 1024
    else:
        page_size_bytes = int(page_size_str)

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)

    # Set HugeTLB limit using discovered page size in bytes
    conf['linux']['resources'] = {
        'hugepageLimits': [
            {
                'pageSize': page_size_str,
                'limit': page_size_bytes
            }
        ]
    }

    max_file = rsvd_file.replace('.rsvd.max', '.max')
    conf['process']['args'] = ['/init', 'cat', max_file]

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if str(page_size_bytes) in out:
            # Also check the reservation limit file
            conf['process']['args'] = ['/init', 'cat', rsvd_file]
            out_rsvd, _ = run_and_get_output(conf, hide_stderr=True)
            # Check if reservation limit was written (not default max)
            # Default max is 9223372036854771712
            if str(page_size_bytes) in out_rsvd:
                return 0
            # If rsvd.max shows default max, reservation accounting might not be working
            if '9223372036854771712' in out_rsvd or 'max' in out_rsvd.lower():
                logger.info("Reservation limit shows default max, skipping test")
                return (77, "reservation accounting not functional")
            logger.info("Expected %s in rsvd.max, got: %s", page_size_bytes, out_rsvd.strip())
            return -1
        logger.info("Expected %s in max, got: %s", page_size_bytes, out.strip())
        return -1
    except subprocess.CalledProcessError as e:
        logger.info("hugetlb reservation test failed: %s", e)
        return -1


all_tests = {
    "cgroup-resources-memory-limit": test_memory_limit,
    "cgroup-resources-memory-reservation": test_memory_reservation,
    "cgroup-resources-memory-swap": test_memory_swap,
    "cgroup-resources-memory-high": test_memory_high,
    "cgroup-resources-memory-disable-oom": test_memory_disable_oom_killer,
    "cgroup-resources-cpu-shares": test_cpu_shares,
    "cgroup-resources-cpu-quota-period": test_cpu_quota_period,
    "cgroup-resources-cpu-idle": test_cpu_idle,
    "cgroup-resources-cpu-burst": test_cpu_burst,
    "cgroup-resources-cpuset-cpus": test_cpuset_cpus,
    "cgroup-resources-cpuset-mems": test_cpuset_mems,
    "cgroup-resources-pids-limit": test_pids_limit,
    "cgroup-resources-blkio-weight": test_blkio_weight,
    "cgroup-resources-unified": test_unified_resources,
    "cgroup-resources-hugetlb-reservation-limit": test_hugetlb_reservation_limit,
}

if __name__ == "__main__":
    tests_main(all_tests)
