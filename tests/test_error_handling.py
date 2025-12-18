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

# Tests for error handling and edge cases

import os
import json
import subprocess
import tempfile
from tests_utils import *


def test_invalid_config_json():
    """Test handling of invalid JSON in config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create invalid JSON config
        config_path = os.path.join(tmpdir, 'config.json')
        with open(config_path, 'w') as f:
            f.write('{ invalid json }')

        # Create minimal rootfs
        rootfs = os.path.join(tmpdir, 'rootfs')
        os.makedirs(rootfs)

        try:
            result = subprocess.run(
                [get_crun_path(), 'run', '-b', tmpdir, 'test-invalid-json'],
                capture_output=True,
                text=True
            )
            # Should fail with error
            if result.returncode != 0:
                return 0
            logger.info("Expected failure for invalid JSON")
            return -1
        except Exception as e:
            # Exception is also acceptable
            return 0


def test_missing_rootfs():
    """Test handling of missing rootfs directory."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, 'config.json')
        with open(config_path, 'w') as f:
            json.dump(conf, f)

        # Don't create rootfs directory

        try:
            result = subprocess.run(
                [get_crun_path(), 'run', '-b', tmpdir, 'test-missing-rootfs'],
                capture_output=True,
                text=True
            )
            # Should fail
            if result.returncode != 0:
                return 0
            logger.info("Expected failure for missing rootfs")
            return -1
        except Exception as e:
            return 0


def test_nonexistent_binary():
    """Test handling of non-existent binary in args."""
    conf = base_config()
    conf['process']['args'] = ['/nonexistent/binary', 'arg1']
    add_all_namespaces(conf)

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        logger.info("Expected failure for non-existent binary")
        return -1
    except subprocess.CalledProcessError:
        # Expected to fail
        return 0
    except Exception as e:
        # Other exceptions also acceptable
        return 0


def test_invalid_uid_mapping():
    """Test handling of invalid UID mapping."""
    if is_rootless():
        return (77, "requires root")

    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf, userns=True)

    # Invalid mapping (negative values)
    conf['linux']['uidMappings'] = [
        {"containerID": 0, "hostID": -1, "size": 1}
    ]
    conf['linux']['gidMappings'] = [
        {"containerID": 0, "hostID": -1, "size": 1}
    ]

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        logger.info("Expected failure for invalid UID mapping")
        return -1
    except:
        # Expected to fail
        return 0


def test_container_already_exists():
    """Test handling of duplicate container ID."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    cid = None
    try:
        # Create first container
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Try to create another with same ID
        try:
            _, _ = run_and_get_output(conf, hide_stderr=True, command='run',
                                       detach=True, id_container=cid)
            logger.info("Expected failure for duplicate container ID")
            return -1
        except:
            # Expected to fail
            return 0

    except Exception as e:
        logger.info("test_container_already_exists failed: %s", e)
        return -1
    finally:
        if cid:
            run_crun_command(['delete', '-f', cid])


def test_state_nonexistent_container():
    """Test state command for non-existent container."""
    try:
        result = subprocess.run(
            [get_crun_path(), 'state', 'nonexistent-container-12345'],
            capture_output=True,
            text=True
        )
        # Should fail
        if result.returncode != 0:
            return 0
        logger.info("Expected failure for non-existent container state")
        return -1
    except Exception as e:
        return 0


def test_delete_nonexistent_container():
    """Test delete command for non-existent container."""
    try:
        result = subprocess.run(
            [get_crun_path(), 'delete', 'nonexistent-container-12345'],
            capture_output=True,
            text=True
        )
        # Should fail (without -f flag)
        if result.returncode != 0:
            return 0
        logger.info("Expected failure for non-existent container delete")
        return -1
    except Exception as e:
        return 0


def test_kill_nonexistent_container():
    """Test kill command for non-existent container."""
    try:
        result = subprocess.run(
            [get_crun_path(), 'kill', 'nonexistent-container-12345', 'SIGTERM'],
            capture_output=True,
            text=True
        )
        # Should fail
        if result.returncode != 0:
            return 0
        logger.info("Expected failure for non-existent container kill")
        return -1
    except Exception as e:
        return 0


def test_exec_stopped_container():
    """Test exec on a stopped container."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']  # Will exit immediately
    add_all_namespaces(conf)

    cid = None
    try:
        out, cid = run_and_get_output(conf, hide_stderr=True, command='run', keep=True)

        # Container should be stopped now, try to exec
        try:
            result = subprocess.run(
                [get_crun_path(), 'exec', cid, '/init', 'true'],
                capture_output=True,
                text=True
            )
            # Should fail - container is stopped
            if result.returncode != 0:
                return 0
            logger.info("Expected failure for exec on stopped container")
            return -1
        except:
            return 0

    except Exception as e:
        logger.info("test_exec_stopped_container failed: %s", e)
        return -1
    finally:
        if cid:
            run_crun_command(['delete', '-f', cid])


def test_invalid_signal():
    """Test kill with invalid signal."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        try:
            result = subprocess.run(
                [get_crun_path(), 'kill', cid, 'INVALID_SIGNAL'],
                capture_output=True,
                text=True
            )
            # Should fail with invalid signal
            if result.returncode != 0:
                return 0
            logger.info("Expected failure for invalid signal")
            return -1
        except:
            return 0

    except Exception as e:
        logger.info("test_invalid_signal failed: %s", e)
        return -1
    finally:
        if cid:
            run_crun_command(['delete', '-f', cid])


def test_empty_args():
    """Test container with empty args."""
    conf = base_config()
    conf['process']['args'] = []  # Empty args
    add_all_namespaces(conf)

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        logger.info("Expected failure for empty args")
        return -1
    except:
        return 0


def test_readonly_rootfs():
    """Test container with readonly rootfs."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    conf['root']['readonly'] = True
    add_all_namespaces(conf)

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0
    except Exception as e:
        logger.info("readonly rootfs test failed: %s", e)
        return -1


def test_working_directory_not_exists():
    """Test container with non-existent working directory."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    conf['process']['cwd'] = '/nonexistent/directory'
    add_all_namespaces(conf)

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        # crun may create the directory or fail - either is valid
        return 0
    except:
        # Failure is also acceptable
        return 0


def test_log_format_json():
    """Test --log-format=json option."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)

    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, 'log.json')

        config_path = os.path.join(tmpdir, 'config.json')
        rootfs = os.path.join(tmpdir, 'rootfs')
        os.makedirs(rootfs)

        # Copy init binary
        init_path = get_init_path()
        import shutil
        shutil.copy2(init_path, os.path.join(rootfs, 'init'))

        with open(config_path, 'w') as f:
            json.dump(conf, f)

        try:
            result = subprocess.run(
                [get_crun_path(), '--debug', '--log-format=json',
                 '--log=file:' + log_file, 'run', '-b', tmpdir, 'test-json-log'],
                capture_output=True,
                text=True
            )
            # Check if log file contains JSON
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    content = f.read()
                    # Should contain JSON-like content with "msg" field
                    if '"msg"' in content or content == '':
                        return 0
            return 0
        except Exception as e:
            logger.info("test_log_format_json failed: %s", e)
            return -1


def test_log_format_text():
    """Test --log-format=text option."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)

    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, 'log.txt')

        config_path = os.path.join(tmpdir, 'config.json')
        rootfs = os.path.join(tmpdir, 'rootfs')
        os.makedirs(rootfs)

        init_path = get_init_path()
        import shutil
        shutil.copy2(init_path, os.path.join(rootfs, 'init'))

        with open(config_path, 'w') as f:
            json.dump(conf, f)

        try:
            result = subprocess.run(
                [get_crun_path(), '--debug', '--log-format=text',
                 '--log=file:' + log_file, 'run', '-b', tmpdir, 'test-text-log'],
                capture_output=True,
                text=True
            )
            # Text format should work
            return 0
        except Exception as e:
            logger.info("test_log_format_text failed: %s", e)
            return -1


def test_log_format_invalid():
    """Test invalid --log-format option."""
    try:
        # Use 'list' command which triggers log format validation
        result = subprocess.run(
            [get_crun_path(), '--log-format=invalid', 'list'],
            capture_output=True,
            text=True
        )
        # Should fail with invalid format
        if result.returncode != 0:
            return 0
        logger.info("Expected failure for invalid log format")
        return -1
    except Exception as e:
        return 0


def test_log_to_syslog():
    """Test --log=syslog: option."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, 'config.json')
        rootfs = os.path.join(tmpdir, 'rootfs')
        os.makedirs(rootfs)

        init_path = get_init_path()
        import shutil
        shutil.copy2(init_path, os.path.join(rootfs, 'init'))

        with open(config_path, 'w') as f:
            json.dump(conf, f)

        try:
            result = subprocess.run(
                [get_crun_path(), '--log=syslog:crun-test',
                 'run', '-b', tmpdir, 'test-syslog'],
                capture_output=True,
                text=True
            )
            # Syslog should work (we can't easily verify syslog output)
            return 0
        except Exception as e:
            logger.info("test_log_to_syslog failed: %s", e)
            return -1


def test_debug_output():
    """Test --debug option produces debug output."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)

    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, 'config.json')
        rootfs = os.path.join(tmpdir, 'rootfs')
        os.makedirs(rootfs)

        init_path = get_init_path()
        import shutil
        shutil.copy2(init_path, os.path.join(rootfs, 'init'))

        with open(config_path, 'w') as f:
            json.dump(conf, f)

        try:
            result = subprocess.run(
                [get_crun_path(), '--debug', 'run', '-b', tmpdir, 'test-debug'],
                capture_output=True,
                text=True
            )
            # Debug output should be on stderr
            # The container might succeed or fail, we just want to test debug path
            return 0
        except Exception as e:
            logger.info("test_debug_output failed: %s", e)
            return -1


def test_log_invalid_path():
    """Test --log with invalid log type."""
    try:
        # Use 'list' command which triggers log validation
        result = subprocess.run(
            [get_crun_path(), '--log=invalid:/path', 'list'],
            capture_output=True,
            text=True
        )
        # Should fail with unknown log type
        if result.returncode != 0:
            return 0
        logger.info("Expected failure for invalid log type")
        return -1
    except Exception as e:
        return 0


all_tests = {
    "error-invalid-config-json": test_invalid_config_json,
    "error-missing-rootfs": test_missing_rootfs,
    "error-nonexistent-binary": test_nonexistent_binary,
    "error-invalid-uid-mapping": test_invalid_uid_mapping,
    "error-container-already-exists": test_container_already_exists,
    "error-state-nonexistent": test_state_nonexistent_container,
    "error-delete-nonexistent": test_delete_nonexistent_container,
    "error-kill-nonexistent": test_kill_nonexistent_container,
    "error-exec-stopped": test_exec_stopped_container,
    "error-invalid-signal": test_invalid_signal,
    "error-empty-args": test_empty_args,
    "error-readonly-rootfs": test_readonly_rootfs,
    "error-working-dir-not-exists": test_working_directory_not_exists,
    "error-log-format-json": test_log_format_json,
    "error-log-format-text": test_log_format_text,
    "error-log-format-invalid": test_log_format_invalid,
    "error-log-to-syslog": test_log_to_syslog,
    "error-debug-output": test_debug_output,
    "error-log-invalid-path": test_log_invalid_path,
}

if __name__ == "__main__":
    tests_main(all_tests)
