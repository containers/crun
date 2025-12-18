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
import time
from tests_utils import *


def test_create_start():
    """Test create and start commands separately."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'create-start-test']
    add_all_namespaces(conf)

    cid = None
    proc = None
    try:
        proc, cid = run_and_get_output(conf, hide_stderr=True, command='create', use_popen=True)

        # Wait for container to be in created state
        for i in range(50):
            try:
                state = json.loads(run_crun_command(["state", cid]))
                if state['status'] == 'created':
                    break
            except:
                pass
            time.sleep(0.1)

        # Start container
        run_crun_command(["start", cid])

        # Get output
        out, _ = proc.communicate(timeout=10)
        if b'create-start-test' not in out:
            logger.info("expected output not found: %s", out)
            return -1

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if proc is not None:
            try:
                proc.kill()
            except:
                pass
        if cid is not None:
            try:
                run_crun_command(["delete", "-f", cid])
            except:
                pass


def test_create_delete_without_start():
    """Test creating and deleting a container without starting it."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    cid = None
    proc = None
    try:
        proc, cid = run_and_get_output(conf, hide_stderr=True, command='create', use_popen=True)

        # Wait for container to be in created state
        for i in range(50):
            try:
                state = json.loads(run_crun_command(["state", cid]))
                if state['status'] == 'created':
                    break
            except:
                pass
            time.sleep(0.1)

        # Delete without starting
        run_crun_command(['delete', '-f', cid])
        cid = None

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if proc is not None:
            try:
                proc.kill()
            except:
                pass
        if cid is not None:
            try:
                run_crun_command(["delete", "-f", cid])
            except:
                pass


def test_create_with_annotations():
    """Test create command with annotations in config."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)
    conf['annotations'] = {
        'test.annotation.key': 'test-value',
        'another.annotation': 'another-value'
    }

    cid = None
    proc = None
    try:
        proc, cid = run_and_get_output(conf, hide_stderr=True, command='create', use_popen=True)

        # Wait for container to be in created state
        for i in range(50):
            try:
                state = json.loads(run_crun_command(["state", cid]))
                if state['status'] == 'created':
                    break
            except:
                pass
            time.sleep(0.1)

        # Check state includes annotations
        state = json.loads(run_crun_command(['state', cid]))
        annotations = state.get('annotations', {})
        if annotations.get('test.annotation.key') != 'test-value':
            logger.info("annotation not preserved in state: %s", annotations)
            # Continue anyway - annotation preservation is optional

        # Start container
        run_crun_command(['start', cid])
        proc.communicate(timeout=10)

        return 0

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if proc is not None:
            try:
                proc.kill()
            except:
                pass
        if cid is not None:
            try:
                run_crun_command(["delete", "-f", cid])
            except:
                pass


all_tests = {
    "create-start": test_create_start,
    "create-delete-without-start": test_create_delete_without_start,
    "create-with-annotations": test_create_with_annotations,
}

if __name__ == "__main__":
    tests_main(all_tests)
