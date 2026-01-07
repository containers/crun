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
from tests_utils import *

def test_fail_prestart():
    conf = base_config()
    conf['hooks'] = {"prestart" : [{"path" : "/bin/false"}]}
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
    except:
        return 0
    return -1

def test_success_prestart():
    conf = base_config()
    conf['hooks'] = {"prestart" : [{"path" : "/bin/true"}]}
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
    except:
        return -1
    return 0

def test_hook_env_inherit():
    conf = base_config()
    path = os.getenv("PATH")

    hook = {"path" : "/bin/sh", "args" : ["/bin/sh", "-c", "test \"$PATH\" = %s" % path]}
    conf['hooks'] = {"prestart" : [hook]}

    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
    except:
        return -1
    return 0

def test_hook_env_no_inherit():
    conf = base_config()

    hook = {"path" : "/bin/sh", "env": ["PATH=/foo"], "args" : ["/bin/sh", "-c", "/bin/test \"$PATH\" == '/foo'"]}
    conf['hooks'] = {"prestart" : [hook]}

    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
    except:
        return -1
    return 0


def test_fail_poststart():
    """Test that a failing poststart hook causes container start to fail."""
    conf = base_config()
    conf['hooks'] = {"poststart" : [{"path" : "/bin/false"}]}
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
    except:
        return 0
    return -1

def test_success_poststart():
    """Test that a successful poststart hook does not cause container start to fail."""
    conf = base_config()
    conf['hooks'] = {"poststart" : [{"path" : "/bin/true"}]}
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
    except:
        return -1
    return 0

def test_poststart_hook():
    """Test poststart hook is called after container starts."""
    if is_rootless():
        return (77, "requires root privileges")

    import tempfile

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']

    cid = None
    marker_file = None
    try:
        # Create a marker file path
        with tempfile.NamedTemporaryFile(delete=False) as f:
            marker_file = f.name

        # Remove it so we can verify the hook creates it
        os.unlink(marker_file)

        hook = {
            "path": "/bin/touch",
            "args": ["/bin/touch", marker_file]
        }
        conf['hooks'] = {"poststart": [hook]}

        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Check if the marker file was created
        if os.path.exists(marker_file):
            return 0

        logger.info("poststart hook did not create marker file")
        return -1

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        if marker_file and os.path.exists(marker_file):
            os.unlink(marker_file)


def test_poststop_hook():
    """Test poststop hook is called after container stops."""
    if is_rootless():
        return (77, "requires root privileges")

    import tempfile
    import time

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'true']

    marker_file = None
    try:
        # Create a marker file path
        with tempfile.NamedTemporaryFile(delete=False) as f:
            marker_file = f.name

        # Remove it so we can verify the hook creates it
        os.unlink(marker_file)

        hook = {
            "path": "/bin/touch",
            "args": ["/bin/touch", marker_file]
        }
        conf['hooks'] = {"poststop": [hook]}

        # Run container that exits quickly
        run_and_get_output(conf, hide_stderr=True)

        # Give the hook time to execute
        time.sleep(0.5)

        # Check if the marker file was created
        if os.path.exists(marker_file):
            return 0

        logger.info("poststop hook did not create marker file")
        return -1

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if marker_file and os.path.exists(marker_file):
            os.unlink(marker_file)


def test_createRuntime_hook():
    """Test createRuntime hook."""
    conf = base_config()
    add_all_namespaces(conf)

    hook = {"path": "/bin/true"}
    conf['hooks'] = {"createRuntime": [hook]}

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_createContainer_hook():
    """Test createContainer hook."""
    conf = base_config()
    add_all_namespaces(conf)

    hook = {"path": "/bin/true"}
    conf['hooks'] = {"createContainer": [hook]}

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_startContainer_hook():
    """Test startContainer hook (runs inside container namespace)."""
    conf = base_config()
    add_all_namespaces(conf)

    # startContainer hook runs inside the container, so use /init
    hook = {"path": "/init", "args": ["/init", "true"]}
    conf['hooks'] = {"startContainer": [hook]}

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        return 0
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1


def test_hook_with_timeout():
    """Test hook timeout is enforced."""
    conf = base_config()
    add_all_namespaces(conf)

    # Hook that sleeps longer than timeout
    hook = {
        "path": "/bin/sleep",
        "args": ["/bin/sleep", "10"],
        "timeout": 1  # 1 second timeout
    }
    conf['hooks'] = {"prestart": [hook]}

    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        # If container ran successfully, timeout wasn't enforced properly
        logger.info("hook timeout not enforced")
        return -1
    except:
        # Expected - hook should timeout and fail
        return 0


def test_hook_receives_state():
    """Test that hooks receive container state on stdin."""
    if is_rootless():
        return (77, "requires root privileges")

    import tempfile
    import json

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'true']

    state_file = None
    try:
        # Create a temp file to capture state
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            state_file = f.name

        # Hook script that saves stdin (state) to file
        hook = {
            "path": "/bin/sh",
            "args": ["/bin/sh", "-c", "cat > " + state_file]
        }
        conf['hooks'] = {"prestart": [hook]}

        run_and_get_output(conf, hide_stderr=True)

        # Verify state was written and is valid JSON
        if os.path.exists(state_file) and os.path.getsize(state_file) > 0:
            with open(state_file) as f:
                state = json.load(f)
                # Basic validation of state structure
                if 'ociVersion' in state or 'id' in state or 'bundle' in state:
                    return 0

        logger.info("hook did not receive valid state")
        return -1

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if state_file and os.path.exists(state_file):
            os.unlink(state_file)


def test_multiple_hooks():
    """Test multiple hooks of the same type run in order."""
    if is_rootless():
        return (77, "requires root privileges")

    import tempfile

    conf = base_config()
    add_all_namespaces(conf)

    marker_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            marker_file = f.name

        # First hook writes "1", second appends "2"
        hook1 = {
            "path": "/bin/sh",
            "args": ["/bin/sh", "-c", "echo -n 1 > " + marker_file]
        }
        hook2 = {
            "path": "/bin/sh",
            "args": ["/bin/sh", "-c", "echo -n 2 >> " + marker_file]
        }
        conf['hooks'] = {"prestart": [hook1, hook2]}

        run_and_get_output(conf, hide_stderr=True)

        # Verify both hooks ran in order
        if os.path.exists(marker_file):
            with open(marker_file) as f:
                content = f.read()
                if content == "12":
                    return 0
                logger.info("hooks ran but order wrong: %s", content)
                return -1

        logger.info("marker file not created")
        return -1

    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if marker_file and os.path.exists(marker_file):
            os.unlink(marker_file)


def test_annotation_hook_stdout_stderr():
    """Test run.oci.hooks.stdout and run.oci.hooks.stderr annotations."""
    if is_rootless():
        return (77, "requires root privileges")

    import tempfile

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'true']

    stdout_file = None
    stderr_file = None
    try:
        # Create temp files for hook output
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            stdout_file = f.name
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            stderr_file = f.name

        # Hook that writes to stdout and stderr
        hook = {
            "path": "/bin/sh",
            "args": ["/bin/sh", "-c", "echo 'stdout message' && echo 'stderr message' >&2"]
        }
        conf['hooks'] = {"prestart": [hook]}

        # Add annotations for hook output redirection
        if 'annotations' not in conf:
            conf['annotations'] = {}
        conf['annotations']['run.oci.hooks.stdout'] = stdout_file
        conf['annotations']['run.oci.hooks.stderr'] = stderr_file

        run_and_get_output(conf, hide_stderr=True)

        # Verify hook stdout was redirected
        if not os.path.exists(stdout_file):
            logger.info("hook stdout file not created")
            return -1

        with open(stdout_file) as f:
            stdout_content = f.read()
            if "stdout message" not in stdout_content:
                logger.info("hook stdout not redirected properly: %s", stdout_content)
                return -1

        # Verify hook stderr was redirected
        if not os.path.exists(stderr_file):
            logger.info("hook stderr file not created")
            return -1

        with open(stderr_file) as f:
            stderr_content = f.read()
            if "stderr message" not in stderr_content:
                logger.info("hook stderr not redirected properly: %s", stderr_content)
                return -1

        logger.info("hook stdout/stderr redirection successful")
        return 0

    except subprocess.CalledProcessError as e:
        output = e.output.decode('utf-8', errors='ignore') if e.output else ''
        if any(x in output.lower() for x in ["mount", "proc", "permission", "rootfs", "private", "busy"]):
            return (77, "not available in nested namespaces")
        logger.info("test failed: %s", e)
        return -1
    except Exception as e:
        logger.info("test failed: %s", e)
        return -1
    finally:
        if stdout_file and os.path.exists(stdout_file):
            os.unlink(stdout_file)
        if stderr_file and os.path.exists(stderr_file):
            os.unlink(stderr_file)


all_tests = {
    "test-fail-prestart" : test_fail_prestart,
    "test-success-prestart" : test_success_prestart,
    "test-fail-poststart" : test_fail_poststart,
    "test-success-poststart" : test_success_poststart,
    "test-hook-env-inherit" : test_hook_env_inherit,
    "test-hook-env-no-inherit" : test_hook_env_no_inherit,
    "test-poststart-hook": test_poststart_hook,
    "test-poststop-hook": test_poststop_hook,
    "test-createRuntime-hook": test_createRuntime_hook,
    "test-createContainer-hook": test_createContainer_hook,
    "test-startContainer-hook": test_startContainer_hook,
    "test-hook-with-timeout": test_hook_with_timeout,
    "test-hook-receives-state": test_hook_receives_state,
    "test-multiple-hooks": test_multiple_hooks,
    "test-annotation-hook-stdout-stderr": test_annotation_hook_stdout_stderr,
}

if __name__ == "__main__":
    tests_main(all_tests)
