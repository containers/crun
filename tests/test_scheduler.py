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
    """Test SCHED_DEADLINE scheduler policy with all parameters (working case)."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")
    if not is_sched_deadline_available():
        return (77, "SCHED_DEADLINE not available in kernel")

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
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_deadline_no_period():
    """Test SCHED_DEADLINE scheduler policy without period (should work - kernel allows it)."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")
    if not is_sched_deadline_available():
        return (77, "SCHED_DEADLINE not available in kernel")

    conf = base_config()
    add_all_namespaces(conf)

    # SCHED_DEADLINE with runtime and deadline but no period
    # Kernel should accept this and use deadline as period
    conf['process']['scheduler'] = {
        'policy': 'SCHED_DEADLINE',
        'runtime': 10000000,    # 10ms
        'deadline': 20000000    # 20ms, no period
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0  # Should succeed

    except subprocess.CalledProcessError as e:
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
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
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_deadline_missing_runtime():
    """Test SCHED_DEADLINE validation - missing runtime parameter."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")
    if not is_sched_deadline_available():
        return (77, "SCHED_DEADLINE not available in kernel")

    conf = base_config()
    add_all_namespaces(conf)

    # Missing runtime parameter
    conf['process']['scheduler'] = {
        'policy': 'SCHED_DEADLINE',
        'deadline': 20000000,   # 20ms
        'period': 20000000      # 20ms
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should have failed due to missing runtime
        return -1

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "sched_setattr: `SCHED_DEADLINE` requires `runtime`" in output:
            return 0  # Expected validation error
        logger.info("unexpected error: %s", output)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_deadline_missing_deadline():
    """Test SCHED_DEADLINE validation - missing deadline parameter."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")
    if not is_sched_deadline_available():
        return (77, "SCHED_DEADLINE not available in kernel")

    conf = base_config()
    add_all_namespaces(conf)

    # Missing deadline parameter
    conf['process']['scheduler'] = {
        'policy': 'SCHED_DEADLINE',
        'runtime': 10000000,    # 10ms
        'period': 20000000      # 20ms
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should have failed due to missing deadline
        return -1

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "sched_setattr: `SCHED_DEADLINE` requires `deadline`" in output:
            return 0  # Expected validation error
        logger.info("unexpected error: %s", output)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1




def test_scheduler_deadline_zero_runtime():
    """Test SCHED_DEADLINE validation - zero runtime."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")
    if not is_sched_deadline_available():
        return (77, "SCHED_DEADLINE not available in kernel")

    conf = base_config()
    add_all_namespaces(conf)

    # Zero runtime
    conf['process']['scheduler'] = {
        'policy': 'SCHED_DEADLINE',
        'runtime': 0,
        'deadline': 20000000,   # 20ms
        'period': 20000000      # 20ms
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should have failed due to zero runtime
        return -1

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "sched_setattr: `SCHED_DEADLINE` runtime must be greater than 0" in output:
            return 0  # Expected validation error
        logger.info("unexpected error: %s", output)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_deadline_invalid_order():
    """Test SCHED_DEADLINE validation - runtime > deadline."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")
    if not is_sched_deadline_available():
        return (77, "SCHED_DEADLINE not available in kernel")

    conf = base_config()
    add_all_namespaces(conf)

    # runtime > deadline (invalid)
    conf['process']['scheduler'] = {
        'policy': 'SCHED_DEADLINE',
        'runtime': 30000000,    # 30ms
        'deadline': 20000000,   # 20ms
        'period': 40000000      # 40ms
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should have failed due to invalid order
        return -1

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "sched_setattr: `SCHED_DEADLINE` runtime" in output and "must be <=" in output and "deadline" in output:
            return 0  # Expected validation error
        logger.info("unexpected error: %s", output)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_deadline_invalid_deadline_period():
    """Test SCHED_DEADLINE validation - deadline > period."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")
    if not is_sched_deadline_available():
        return (77, "SCHED_DEADLINE not available in kernel")

    conf = base_config()
    add_all_namespaces(conf)

    # deadline > period (invalid)
    conf['process']['scheduler'] = {
        'policy': 'SCHED_DEADLINE',
        'runtime': 10000000,    # 10ms
        'deadline': 30000000,   # 30ms
        'period': 20000000      # 20ms
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should have failed due to invalid order
        return -1

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "sched_setattr: `SCHED_DEADLINE` deadline" in output and "must be <=" in output and "period" in output:
            return 0  # Expected validation error
        logger.info("unexpected error: %s", output)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_deadline_too_small_runtime():
    """Test SCHED_DEADLINE validation - runtime < min."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")
    if not is_sched_deadline_available():
        return (77, "SCHED_DEADLINE not available in kernel")

    conf = base_config()
    add_all_namespaces(conf)

    conf['process']['scheduler'] = {
        'policy': 'SCHED_DEADLINE',
        'runtime': 1023,        # too small
        'deadline': 10000000,   # 10ms
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should have failed due to too small runtime.
        return -1

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "sched_setattr: `SCHED_DEADLINE` runtime " in output and " must be between " in output:
            return 0  # Expected validation error
        logger.info("unexpected error: %s", output)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_scheduler_deadline_too_big_runtime():
    """Test SCHED_DEADLINE validation - runtime > max."""
    if is_rootless():
        return (77, "SCHED_DEADLINE requires root")
    if not is_sched_deadline_available():
        return (77, "SCHED_DEADLINE not available in kernel")

    conf = base_config()
    add_all_namespaces(conf)

    conf['process']['scheduler'] = {
        'policy': 'SCHED_DEADLINE',
        'runtime': 9223372036854775809,
        'deadline': 9223372036854775810,
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=False)
        # Should have failed due to too big runtime.
        return -1

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "sched_setattr: `SCHED_DEADLINE` runtime " in output and " must be between " in output:
            return 0  # Expected validation error
        logger.info("unexpected error: %s", output)
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
    "scheduler-deadline-no-period": test_scheduler_deadline_no_period,
    "scheduler-flags": test_scheduler_flags,
    "scheduler-deadline-missing-runtime": test_scheduler_deadline_missing_runtime,
    "scheduler-deadline-missing-deadline": test_scheduler_deadline_missing_deadline,
    "scheduler-deadline-zero-runtime": test_scheduler_deadline_zero_runtime,
    "scheduler-deadline-invalid-order": test_scheduler_deadline_invalid_order,
    "scheduler-deadline-invalid-deadline-period": test_scheduler_deadline_invalid_deadline_period,
    "scheduler-deadline-too-small-runtime": test_scheduler_deadline_too_small_runtime,
    "scheduler-deadline-too-big-runtime": test_scheduler_deadline_too_big_runtime,
}

if __name__ == "__main__":
    tests_main(all_tests)
