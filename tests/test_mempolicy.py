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
from tests_utils import *

def check_numa_interleave():
    return os.path.exists("/sys/kernel/mm/mempolicy/weighted_interleave")

def check_numa_hw():
    return os.path.exists("/proc/self/numa_maps")

def check_mempolicy_prerequisites(need_interleave=False):
    """Check all prerequisites for numa mempolicy tests. Returns 77 (skip) if not met, 0 if OK"""
    if not check_numa_hw():
        sys.stderr.write("# numa missing\n")
        return (77, "NUMA hardware not available")
    if need_interleave and not check_numa_interleave():
        sys.stderr.write("# interleave missing\n")
        return (77, "NUMA interleave not supported")

def test_mempolicy_no_conf():
    """Test numa mempolicy without configuration"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { }

    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run')
        sys.stderr.write("# unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_bad_mode():
    """Test numa mempolicy with bad mode"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "BAD_MODE" }

    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run')
        sys.stderr.write("# unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_bad_flag():
    """Test numa mempolicy with bad flag"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_PREFERRED", "flags": ["BADFLAG"] }

    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run')
        sys.stderr.write("# unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_numa_balancing_flag():
    """Test numa mempolicy preferred with numa_balancing flag"""
    if check_mempolicy_prerequisites(need_interleave=True):
        return check_mempolicy_prerequisites(need_interleave=True)

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_PREFERRED", "flags": ["MPOL_F_NUMA_BALANCING"] }

    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run')
        sys.stderr.write("# unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_static_relative_nodes_flags():
    """Test numa mempolicy preferred with numa_balancing flag"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_PREFERRED", "flags": ["MPOL_F_RELATIVE_NODES", "MPOL_F_STATIC_NODES"] }

    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run')
        sys.stderr.write("# unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_no_nodes():
    """Test numa mempolicy without nodes configuration"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_INTERLEAVE" }

    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run')
        sys.stderr.write("# unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_bad_nodes_string():
    """Test numa mempolicy without nodes configuration"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_PREFERRED", "nodes": "bad" }

    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run')
        sys.stderr.write("# unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_bad_nodes_number():
    """Test numa mempolicy without nodes configuration"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_PREFERRED", "nodes": "10284838" }

    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run')
        sys.stderr.write("# unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_default_mode():
    """Test numa mempolicy default mode"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_DEFAULT" }

    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if " default " not in out.splitlines()[1]:
            sys.stderr.write("# Unable to find ' default ' in /proc/self/numa_maps\n")
            sys.stderr.write(out)
            return -1
    except Exception as e:
        sys.stderr.write("# Test failed with exception: %s\n" % str(e))
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_local_mode():
    """Test numa mempolicy local mode"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_LOCAL" }

    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if " local " not in out.splitlines()[1]:
            sys.stderr.write("# Unable to find ' local ' in /proc/self/numa_maps\n")
            sys.stderr.write(out)
            return -1
    except Exception as e:
        sys.stderr.write("# Test failed with exception: %s\n" % str(e))
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_bind_mode():
    """Test numa mempolicy bind mode"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_BIND", "nodes": "0" }

    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if " bind:0 " not in out.splitlines()[1]:
            sys.stderr.write("# Unable to find ' bind:0 ' in /proc/self/numa_maps\n")
            sys.stderr.write(out)
            return -1
    except Exception as e:
        sys.stderr.write("# Test failed with exception: %s\n" % str(e))
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_bind_mode_balancing():
    """Test numa mempolicy bind mode balancing"""
    if check_mempolicy_prerequisites(need_interleave=True):
        return check_mempolicy_prerequisites(need_interleave=True)

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_BIND", "nodes": "0", "flags": ["MPOL_F_NUMA_BALANCING"]}

    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if " bind=balancing:0 " not in out.splitlines()[1]:
            sys.stderr.write("# Unable to find ' bind=balancing:0 ' in /proc/self/numa_maps\n")
            sys.stderr.write(out)
            return -1
    except Exception as e:
        sys.stderr.write("# Test failed with exception: %s\n" % str(e))
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_bind_mode_balancing_relative():
    """Test numa mempolicy bind mode balancing with relative nodes"""
    if check_mempolicy_prerequisites(need_interleave=True):
        return check_mempolicy_prerequisites(need_interleave=True)

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_BIND", "nodes": "0", "flags": ["MPOL_F_NUMA_BALANCING", "MPOL_F_RELATIVE_NODES"]}

    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if " bind=relative|balancing:0 " not in out.splitlines()[1]:
            sys.stderr.write("# Unable to find ' bind=relative|balancing:0 ' in /proc/self/numa_maps\n")
            sys.stderr.write(out)
            return -1
    except Exception as e:
        sys.stderr.write("# Test failed with exception: %s\n" % str(e))
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_preferred_mode_static():
    """Test numa mempolicy preferred mode with static nodes"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_PREFERRED", "nodes": "0", "flags": ["MPOL_F_STATIC_NODES"]}

    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if " prefer=static:0 " not in out.splitlines()[1]:
            sys.stderr.write("# Unable to find ' prefer=static:0 ' in /proc/self/numa_maps\n")
            sys.stderr.write(out)
            return -1
    except Exception as e:
        sys.stderr.write("# Test failed with exception: %s\n" % str(e))
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_preferred_many_mode():
    """Test numa mempolicy preferred many mode with all nodes"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_PREFERRED_MANY", "nodes": "0" }

    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if " prefer (many):0 " not in out.splitlines()[1]:
            sys.stderr.write("# Unable to find ' prefer (many):0 ' in /proc/self/numa_maps\n")
            sys.stderr.write(out)
            return -1
    except Exception as e:
        sys.stderr.write("# Test failed with exception: %s\n" % str(e))
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_interleave_mode():
    """Test numa mempolicy interleave mode"""
    if check_mempolicy_prerequisites():
        return check_mempolicy_prerequisites()

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_INTERLEAVE", "nodes": "0" }

    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if " interleave:0 " not in out.splitlines()[1]:
            sys.stderr.write("# Unable to find ' interleave:0 ' in /proc/self/numa_maps\n")
            sys.stderr.write(out)
            return -1
    except Exception as e:
        sys.stderr.write("# Test failed with exception: %s\n" % str(e))
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_mempolicy_weighted_interleave_mode():
    """Test numa mempolicy weighted interleave mode"""
    if check_mempolicy_prerequisites(need_interleave=True):
        return check_mempolicy_prerequisites(need_interleave=True)

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/numa_maps']
    add_all_namespaces(conf)
    conf['linux']['memoryPolicy'] = { "mode": "MPOL_WEIGHTED_INTERLEAVE", "nodes": "0" }

    cid = None
    try:
        out, cid = run_and_get_output(conf, command='run')
        if " weighted interleave:0 " not in out.splitlines()[1]:
            sys.stderr.write("# Unable to find ' weighted interleave ' in /proc/self/numa_maps\n")
            sys.stderr.write(out)
            return -1
    except Exception as e:
        sys.stderr.write("# Test failed with exception: %s\n" % str(e))
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

all_tests = {
    "mempolicy-no-conf": test_mempolicy_no_conf,
    "mempolicy-bad-mode": test_mempolicy_bad_mode,
    "mempolicy-bad-flag": test_mempolicy_bad_flag,
    "mempolicy-numa-balancing-flag": test_mempolicy_numa_balancing_flag,
    "mempolicy-static-relative-nodes-flags": test_mempolicy_static_relative_nodes_flags,
    "mempolicy-no-nodes": test_mempolicy_no_nodes,
    "mempolicy-bad-nodes-string": test_mempolicy_bad_nodes_string,
    "mempolicy-bad-nodes-number": test_mempolicy_bad_nodes_number,
    "mempolicy-default-mode": test_mempolicy_default_mode,
    "mempolicy-local-mode": test_mempolicy_local_mode,
    "mempolicy-bind-mode": test_mempolicy_bind_mode,
    "mempolicy-bind-mode-balancing": test_mempolicy_bind_mode_balancing,
    "mempolicy-bind-mode-balancing-relative": test_mempolicy_bind_mode_balancing_relative,
    "mempolicy-preferred-mode-static": test_mempolicy_preferred_mode_static,
    "mempolicy-preferred-many-mode-all-nodes": test_mempolicy_preferred_many_mode,
    "mempolicy-interleave-mode": test_mempolicy_interleave_mode,
    "mempolicy-weighted-interleave-mode": test_mempolicy_weighted_interleave_mode,
}

if __name__ == "__main__":
    tests_main(all_tests)
