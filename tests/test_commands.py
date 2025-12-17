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
import tempfile
import time
from tests_utils import *

def test_pause_unpause():
    """Test pause and unpause commands."""
    if is_rootless():
        return (77, "requires root for cgroup freezer")

    conf = base_config()
    add_all_namespaces(conf, cgroupns=True)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Verify container is running
        state = json.loads(run_crun_command(['state', cid]))
        if state['status'] != 'running':
            logger.info("container not in running state: %s", state['status'])
            return -1

        # Pause the container
        run_crun_command(['pause', cid])

        # Verify container is paused
        state = json.loads(run_crun_command(['state', cid]))
        if state['status'] != 'paused':
            logger.info("container not in paused state: %s", state['status'])
            return -1

        # Unpause the container
        run_crun_command(['resume', cid])

        # Verify container is running again
        state = json.loads(run_crun_command(['state', cid]))
        if state['status'] != 'running':
            logger.info("container not in running state after resume: %s", state['status'])
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


def test_kill_signal():
    """Test kill command with various signals."""

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Verify container is running
        state = json.loads(run_crun_command(['state', cid]))
        if state['status'] != 'running':
            logger.info("container not in running state: %s", state['status'])
            return -1

        # Send SIGKILL
        run_crun_command(['kill', cid, 'SIGKILL'])

        # Wait for container to stop
        time.sleep(0.5)

        # Verify container is stopped
        state = json.loads(run_crun_command(['state', cid]))
        if state['status'] != 'stopped':
            logger.info("container not stopped after SIGKILL: %s", state['status'])
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_kill_signal_number():
    """Test kill command with signal number."""

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Send signal 9 (SIGKILL)
        run_crun_command(['kill', cid, '9'])

        # Wait for container to stop
        time.sleep(0.5)

        # Verify container is stopped
        state = json.loads(run_crun_command(['state', cid]))
        if state['status'] != 'stopped':
            logger.info("container not stopped after signal 9: %s", state['status'])
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_list_containers():
    """Test list command."""

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid1 = None
    cid2 = None
    try:
        _, cid1 = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        _, cid2 = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # List containers
        output = run_crun_command(['list', '--format', 'json'])
        containers = json.loads(output)

        # Find our containers in the list
        found_cid1 = False
        found_cid2 = False
        for c in containers:
            if c.get('id') == cid1:
                found_cid1 = True
                if c.get('status') != 'running':
                    logger.info("container %s not running: %s", cid1, c.get('status'))
                    return -1
            if c.get('id') == cid2:
                found_cid2 = True
                if c.get('status') != 'running':
                    logger.info("container %s not running: %s", cid2, c.get('status'))
                    return -1

        if not found_cid1:
            logger.info("container %s not found in list", cid1)
            return -1
        if not found_cid2:
            logger.info("container %s not found in list", cid2)
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid1 is not None:
            run_crun_command(["delete", "-f", cid1])
        if cid2 is not None:
            run_crun_command(["delete", "-f", cid2])




def test_spec_generation():
    """Test spec command generates valid OCI config."""
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate spec
            subprocess.check_call([get_crun_path(), 'spec'], cwd=tmpdir)

            # Verify config.json was created
            config_path = os.path.join(tmpdir, 'config.json')
            if not os.path.exists(config_path):
                logger.info("config.json not created")
                return -1

            # Verify it's valid JSON
            with open(config_path) as f:
                config = json.load(f)

            # Verify basic OCI structure
            if 'ociVersion' not in config:
                logger.info("missing ociVersion")
                return -1
            if 'process' not in config:
                logger.info("missing process")
                return -1
            if 'root' not in config:
                logger.info("missing root")
                return -1

            return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_spec_rootless():
    """Test spec command with --rootless flag."""
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate rootless spec
            subprocess.check_call([get_crun_path(), 'spec', '--rootless'], cwd=tmpdir)

            # Verify config.json was created
            config_path = os.path.join(tmpdir, 'config.json')
            if not os.path.exists(config_path):
                logger.info("config.json not created")
                return -1

            # Verify it's valid JSON
            with open(config_path) as f:
                config = json.load(f)

            # Verify rootless configuration has user namespace
            namespaces = config.get('linux', {}).get('namespaces', [])
            has_user_ns = any(ns.get('type') == 'user' for ns in namespaces)
            if not has_user_ns:
                logger.info("rootless spec missing user namespace")
                return -1

            return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_kill_sigterm():
    """Test kill command with SIGTERM."""

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Send SIGTERM
        run_crun_command(['kill', cid, 'SIGTERM'])

        # Wait for container to stop
        time.sleep(0.5)

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_kill_all():
    """Test kill command with --all flag."""
    if is_rootless():
        return (77, "requires root for cgroup access")

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Kill all processes in container
        run_crun_command(['kill', '--all', cid, 'SIGKILL'])

        # Wait for container to stop
        time.sleep(0.5)

        # Verify container is stopped
        state = json.loads(run_crun_command(['state', cid]))
        if state['status'] != 'stopped':
            logger.info("container not stopped after kill --all: %s", state['status'])
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_list_table_format():
    """Test list command with table format."""

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # List containers with table format (default)
        output = run_crun_command(['list'])

        # Table output should contain column headers
        if 'ID' not in output and 'STATUS' not in output:
            logger.info("table format missing headers: %s", output[:100])
            return -1

        # Should contain our container ID
        if cid not in output:
            logger.info("container %s not in list output", cid)
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_list_quiet():
    """Test list command with quiet flag."""

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # List containers in quiet mode
        output = run_crun_command(['list', '-q'])

        # Quiet mode should just list container IDs
        if cid not in output:
            logger.info("container %s not in quiet list output", cid)
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_ps_table_format():
    """Test ps command with table format."""
    if is_rootless():
        return (77, "requires root for cgroup access")

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Get process list with table format (default)
        output = run_crun_command(['ps', cid])

        # Table output should contain PID header
        if 'PID' not in output:
            logger.info("ps table format missing PID header")
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_state_command():
    """Test state command."""

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Get container state
        output = run_crun_command(['state', cid])
        state = json.loads(output)

        # Verify state structure
        if 'ociVersion' not in state:
            logger.info("state missing ociVersion")
            return -1
        if 'id' not in state:
            logger.info("state missing id")
            return -1
        if state['id'] != cid:
            logger.info("state id mismatch: expected %s, got %s", cid, state['id'])
            return -1
        if 'status' not in state:
            logger.info("state missing status")
            return -1
        if 'pid' not in state:
            logger.info("state missing pid")
            return -1
        if 'bundle' not in state:
            logger.info("state missing bundle")
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])




all_tests = {
    "pause-unpause": test_pause_unpause,
    "kill-signal": test_kill_signal,
    "kill-signal-number": test_kill_signal_number,
    "kill-sigterm": test_kill_sigterm,
    "kill-all": test_kill_all,
    "list-containers": test_list_containers,
    "list-table-format": test_list_table_format,
    "list-quiet": test_list_quiet,
    "ps-table-format": test_ps_table_format,
    "spec-generation": test_spec_generation,
    "spec-rootless": test_spec_rootless,
    "state-command": test_state_command,
}

if __name__ == "__main__":
    tests_main(all_tests)
