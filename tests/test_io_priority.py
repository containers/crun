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
from tests_utils import *


def test_io_priority_best_effort():
    """Test I/O priority with best effort class."""

    conf = base_config()
    add_all_namespaces(conf)

    # Set I/O priority to best effort class with priority 4
    conf['process']['ioPriority'] = {
        'class': 'IOPRIO_CLASS_BE',
        'priority': 4
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "ioprio" in output.lower() or "priority" in output.lower():
            return (77, "I/O priority not supported")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_io_priority_realtime():
    """Test I/O priority with realtime class."""
    if is_rootless():
        return (77, "IOPRIO_CLASS_RT requires CAP_SYS_ADMIN")

    conf = base_config()
    add_all_namespaces(conf)

    # Set I/O priority to realtime class with priority 2
    conf['process']['ioPriority'] = {
        'class': 'IOPRIO_CLASS_RT',
        'priority': 2
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "ioprio" in output.lower() or "priority" in output.lower() or "permission" in output.lower():
            return (77, "I/O realtime priority not supported")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_io_priority_idle():
    """Test I/O priority with idle class."""

    conf = base_config()
    add_all_namespaces(conf)

    # Set I/O priority to idle class
    conf['process']['ioPriority'] = {
        'class': 'IOPRIO_CLASS_IDLE'
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "ioprio" in output.lower() or "priority" in output.lower():
            return (77, "I/O priority not supported")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_io_priority_best_effort_high():
    """Test I/O priority with high best effort priority."""

    conf = base_config()
    add_all_namespaces(conf)

    # Set I/O priority to best effort with priority 0 (highest)
    conf['process']['ioPriority'] = {
        'class': 'IOPRIO_CLASS_BE',
        'priority': 0
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "ioprio" in output.lower() or "priority" in output.lower():
            return (77, "I/O priority not supported")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_io_priority_best_effort_low():
    """Test I/O priority with low best effort priority."""

    conf = base_config()
    add_all_namespaces(conf)

    # Set I/O priority to best effort with priority 7 (lowest)
    conf['process']['ioPriority'] = {
        'class': 'IOPRIO_CLASS_BE',
        'priority': 7
    }

    conf['process']['args'] = ['/init', 'true']

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if "ioprio" in output.lower() or "priority" in output.lower():
            return (77, "I/O priority not supported")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


all_tests = {
    "io-priority-best-effort": test_io_priority_best_effort,
    "io-priority-realtime": test_io_priority_realtime,
    "io-priority-idle": test_io_priority_idle,
    "io-priority-best-effort-high": test_io_priority_best_effort_high,
    "io-priority-best-effort-low": test_io_priority_best_effort_low,
}

if __name__ == "__main__":
    tests_main(all_tests)
