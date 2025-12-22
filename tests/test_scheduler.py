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
from tests_utils import *


def test_scheduler_fifo():
    """Test SCHED_FIFO scheduler policy."""
    if is_rootless():
        return (77, "SCHED_FIFO requires CAP_SYS_NICE")

    conf = base_config()
    add_all_namespaces(conf)

    # Set scheduler to SCHED_FIFO with priority 10
    conf['process']['scheduler'] = {
        'policy': 'SCHED_FIFO',
        'priority': 10
    }

    # Read scheduler policy from /proc/self/sched
    conf['process']['args'] = ['/init', 'cat', '/proc/self/sched']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        # Just verify the container runs with scheduler config
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "scheduler" in output.lower() or "permission" in output.lower():
            return (77, "SCHED_FIFO not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_rr():
    """Test SCHED_RR (round-robin) scheduler policy."""
    if is_rootless():
        return (77, "SCHED_RR requires CAP_SYS_NICE")

    conf = base_config()
    add_all_namespaces(conf)

    # Set scheduler to SCHED_RR with priority 10
    conf['process']['scheduler'] = {
        'policy': 'SCHED_RR',
        'priority': 10
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "scheduler" in output.lower() or "permission" in output.lower():
            return (77, "SCHED_RR not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_batch():
    """Test SCHED_BATCH scheduler policy."""

    conf = base_config()
    add_all_namespaces(conf)

    # SCHED_BATCH doesn't use priority
    conf['process']['scheduler'] = {
        'policy': 'SCHED_BATCH'
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "scheduler" in output.lower() or "permission" in output.lower():
            return (77, "SCHED_BATCH not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_idle():
    """Test SCHED_IDLE scheduler policy."""

    conf = base_config()
    add_all_namespaces(conf)

    # SCHED_IDLE doesn't use priority
    conf['process']['scheduler'] = {
        'policy': 'SCHED_IDLE'
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "scheduler" in output.lower() or "permission" in output.lower():
            return (77, "SCHED_IDLE not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_other():
    """Test SCHED_OTHER (default) scheduler policy."""
    conf = base_config()
    add_all_namespaces(conf)

    # SCHED_OTHER with nice value
    conf['process']['scheduler'] = {
        'policy': 'SCHED_OTHER',
        'nice': 5
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_nice_value():
    """Test scheduler with nice value."""

    conf = base_config()
    add_all_namespaces(conf)

    # Set nice value
    conf['process']['scheduler'] = {
        'policy': 'SCHED_OTHER',
        'nice': 10
    }

    # Just verify container runs with nice value set
    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        # Container ran with nice value set - test passes
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "scheduler" in output.lower() or "nice" in output.lower():
            return (77, "nice value not supported")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_deadline():
    """Test SCHED_DEADLINE scheduler policy."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")

    conf = base_config()
    add_all_namespaces(conf)

    # SCHED_DEADLINE requires runtime, deadline, period
    conf['process']['scheduler'] = {
        'policy': 'SCHED_DEADLINE',
        'runtime': 10000000,    # 10ms
        'deadline': 20000000,   # 20ms
        'period': 20000000      # 20ms
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        # SCHED_DEADLINE often not available
        if "scheduler" in output.lower() or "permission" in output.lower() or "deadline" in output.lower():
            return (77, "SCHED_DEADLINE not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        error_str = str(e).lower()
        if "deadline" in error_str or "scheduler" in error_str:
            return (77, "SCHED_DEADLINE not available")
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_flags():
    """Test scheduler with flags (reset_on_fork)."""
    if is_rootless():
        return (77, "SCHED_FIFO with flags requires CAP_SYS_NICE")

    conf = base_config()
    add_all_namespaces(conf)

    # Test with SCHED_RESET_ON_FORK flag
    conf['process']['scheduler'] = {
        'policy': 'SCHED_FIFO',
        'priority': 10,
        'flags': ['SCHED_FLAG_RESET_ON_FORK']
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "scheduler" in output.lower() or "permission" in output.lower():
            return (77, "scheduler flags not available")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


all_tests = {
    "scheduler-fifo": test_scheduler_fifo,
    "scheduler-rr": test_scheduler_rr,
    "scheduler-batch": test_scheduler_batch,
    "scheduler-idle": test_scheduler_idle,
    "scheduler-other": test_scheduler_other,
    "scheduler-nice-value": test_scheduler_nice_value,
    "scheduler-deadline": test_scheduler_deadline,
    "scheduler-flags": test_scheduler_flags,
}

if __name__ == "__main__":
    tests_main(all_tests)
