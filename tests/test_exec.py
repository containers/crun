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
import re
import shutil
import subprocess
import tempfile
from tests_utils import *
import time

def test_exec():
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        out = run_crun_command(["exec", cid, "/init", "echo", "foo"])
        if "foo" not in out:
            logger.info("exec test failed: expected 'foo' in output")
            logger.info("container ID: %s", cid)
            logger.info("actual output: %s", out)
            return -1
    except Exception as e:
        logger.info("exec test failed with exception: %s", e)
        if cid is not None:
            logger.info("container ID: %s", cid)
        raise
    finally:
        if cid is not None:
            try:
                run_crun_command(["delete", "-f", cid])
            except Exception as cleanup_e:
                logger.info("warning: failed to cleanup container %s: %s", cid, cleanup_e)
    return 0

def test_uid_tty():
    # we need at least two uids
    if is_rootless():
        return 77

    if os.isatty(1) == False:
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    conf['process']['terminal'] = True
    add_all_namespaces(conf)
    cid = None
    ret = 1
    last_error = None
    try:
        cid = "container-%s" % os.getpid()
        proc = run_and_get_output(conf, hide_stderr=True, command='run', id_container=cid, use_popen=True)
        for i in range(0, 500):
            try:
                out = run_crun_command(["exec", "-t", "--user", "1", cid, "/init", "owner", "/proc/self/fd/0"])
                if "1:" in out:
                    ret = 0
                    break
            except Exception as e:
                last_error = e
                pass
            time.sleep(0.01)
        if ret != 0:
            logger.info("uid_tty test failed after 500 attempts")
            logger.info("container ID: %s", cid)
            if last_error:
                logger.info("last error: %s", last_error)
        return ret
    finally:
        if cid is not None:
            try:
                run_crun_command(["delete", "-f", cid])
            except Exception as cleanup_e:
                logger.info("warning: failed to cleanup container %s: %s", cid, cleanup_e)
    return 0

def test_exec_root_netns_with_userns():
    if is_rootless():
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf, netns=False)
    conf['linux']['namespaces'].append({"type" : "network", "path" : "/proc/1/ns/net"})
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        with open("/proc/net/route") as f:
            payload = f.read()
            host_routes = [i.split('\t')[0] for i in payload.split('\n')[1:] if i.strip()]

        out = run_crun_command(["exec", cid, "/init", "cat", "/proc/net/route"])

        container_routes = [i.split('\t')[0] for i in out.split('\n')[1:] if i.strip()]

        if len(container_routes) != len(host_routes):
            logger.info("network namespace test failed: different route count")
            logger.info("host routes (%d): %s", len(host_routes), host_routes)
            logger.info("container routes (%d): %s", len(container_routes), container_routes)
            return -1

        host_routes.sort()
        container_routes.sort()

        for i, (container_route, host_route) in enumerate(zip(container_routes, host_routes)):
            if container_route != host_route:
                logger.info("network namespace test failed: route mismatch at index %d", i)
                logger.info("expected (host): %s", host_route)
                logger.info("actual (container): %s", container_route)
                logger.info("full host routes: %s", host_routes)
                logger.info("full container routes: %s", container_routes)
                return -1
    except Exception as e:
        logger.info("network namespace test failed with exception: %s", e)
        if cid is not None:
            logger.info("container ID: %s", cid)
        raise
    finally:
        if cid is not None:
            try:
                run_crun_command(["delete", "-f", cid])
            except Exception as cleanup_e:
                logger.info("warning: failed to cleanup container %s: %s", cid, cleanup_e)
    return 0

def test_exec_not_exists_helper(detach):
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        try:
            if detach:
                out = run_crun_command(["exec", "-d", cid, "/not.here"])
            else:
                out = run_crun_command(["exec", cid, "/not.here"])
        except Exception as e:
            return 0
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 1

def test_exec_not_exists():
    return test_exec_not_exists_helper(False)

def test_exec_detach_not_exists():
    return test_exec_not_exists_helper(True)

def test_exec_additional_gids():
    if is_rootless():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    tempdir = tempfile.mkdtemp()
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        process_file = os.path.join(tempdir, "process.json")
        with open(process_file, "w") as f:
            json.dump({
	        "user": {
	            "uid": 0,
	            "gid": 0,
                    "additionalGids": [432]
	        },
                "terminal": False,
	        "args": [
                    "/init",
                    "groups"
	        ],
	        "env": [
	            "PATH=/bin",
	            "TERM=xterm"
	        ],
	        "cwd": "/",
	        "noNewPrivileges": True
            }, f)
        out = run_crun_command(["exec", "--process", process_file, cid])
        if "432" not in out:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        shutil.rmtree(tempdir)
    return 0

def test_exec_populate_home_env_from_process_uid():
    if is_rootless():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    tempdir = tempfile.mkdtemp()
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        process_file = os.path.join(tempdir, "process.json")
        with open(process_file, "w") as f:
            json.dump({
	        "user": {
	            "uid": 1000,
	            "gid": 1000,
                    "additionalGids": [1000]
	        },
                "terminal": False,
	        "args": [
                    "/init",
                    "printenv",
                    "HOME"
	        ],
	        "env": [
	            "PATH=/bin",
	            "TERM=xterm"
	        ],
	        "cwd": "/",
	        "noNewPrivileges": True
            }, f)
        out = run_crun_command(["exec", "--process", process_file, cid])
        if "/var/empty" not in out:
           return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        shutil.rmtree(tempdir)
    return 0

def test_exec_add_capability():
    """Specify an additional capability to add to the process"""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    cid = None
    cap_kill_dict = {"CapInh":"0000000000000000", \
                     "CapPrm":"0000000000000020", \
                     "CapEff":"0000000000000020", \
                     "CapBnd":"0000000000000020", \
                     "CapAmb":"0000000000000000"}
    cap_sys_admin_dict = {"CapInh":"0000000000000000", \
                          "CapPrm":"0000000000200000", \
                          "CapEff":"0000000000200000", \
                          "CapBnd":"0000000000200000", \
                          "CapAmb":"0000000000000000"}
    cap_dict = {"CAP_KILL": cap_kill_dict, \
                "CAP_SYS_ADMIN": cap_sys_admin_dict}
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        for cap, value in cap_dict.items():
            out = run_crun_command(["exec", "--cap", cap, cid, "/init", "cat", "/proc/self/status"])
            for i in ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']:
                conf['process']['capabilities'][i] = []
            proc_status = parse_proc_status(out)

            for i in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
                if proc_status[i] != value[i]:
                    return -1

        try:
            run_crun_command(["exec", "--cap", "CAP_UNKNOWN", cid, "/init", "cat", "/proc/self/status"])
            logger.info("CAP_UNKNOWN should be rejected")
            return -1
        except subprocess.CalledProcessError:
            pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_exec_add_env():
    """Add an environment variable"""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    cid = None
    env_args_list = []
    env_dict_orig = {"HOME":"/", "PATH":"/bin", "TERM":"xterm"}
    env_dict_new = {"HOME":"/tmp", "PATH":"/usr/bin","FOO":"BAR"}
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        # check original environment variable
        for env, value in env_dict_orig.items():
            out = run_crun_command(["exec", cid, "/init", "printenv", env])
            if value not in out:
                return -1
        # check that the environment has the key/value pair we added
        for env, value in env_dict_new.items():
            out = run_crun_command(["exec", "--env", "%s=%s" %(env,value), \
                                     cid, "/init", "printenv", env])
            env_args_list.append("%s=%s" %(env,value))
            if value not in out:
                return -1

        # set multiple environment variable at the same time
        out = run_crun_command(["exec", "--env", env_args_list[0], \
                                "-e", env_args_list[1], \
                                "-e", env_args_list[2], \
                                cid, "/init", "printenv", "PATH"])
        if env_dict_new["PATH"] not in out:
            return -1

        # --env must merge with, not replace, the container's default env:
        # PATH from the spec must still be set when only an unrelated var is added.
        out = run_crun_command(["exec", "--env", "FOO=BAR", cid, "/init", "printenv", "PATH"])
        if env_dict_orig["PATH"] not in out:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_exec_set_user():
    """specify the user in the form UID[:GID]"""
    if is_rootless():
        return 77

    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']
    cid = None
    uid_gid_list = ["1000:1000", "0:0", "65535:65535"]

    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        # check current user id
        out = run_crun_command(["exec", cid, "/init", "id"])
        if uid_gid_list[1] not in out:
            return -1
        # check that the uid and gid have the value we added
        for id in uid_gid_list:
            out = run_crun_command(["exec", "--user", id, cid, "/init", "id"])
            if id not in out:
                return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_exec_no_new_privs():
    """Set the no new privileges value for the process"""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        # check original value of NoNewPrivs
        out = run_crun_command(["exec", cid, "/init", "cat", "/proc/self/status"])
        proc_status = parse_proc_status(out)
        if proc_status["NoNewPrivs"] != "0":
            return -1
        out = run_crun_command(["exec", "--no-new-privs", cid, "/init", "cat", "/proc/self/status"])
        # check no new privileges value of NoNewPrivs
        proc_status = parse_proc_status(out)
        if proc_status["NoNewPrivs"] != "1":
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_exec_write_pid_file():
    """Set the no new privileges value for the process"""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    cid = None
    tempdir = tempfile.mkdtemp()
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        pid_file = os.path.join(tempdir, cid)
        out = run_crun_command(["exec", "--pid-file", pid_file, cid, "/init", "echo", "hello"])
        if "hello" not in out:
            return -1
        if not os.path.exists(pid_file):
            return -1

        regu_cont = re.compile(r'\d+')
        with open(pid_file, 'r') as fp:
            contents = fp.read()
            fp.close()
            if not regu_cont.match(contents):
                return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        shutil.rmtree(tempdir)
    return 0

def test_exec_cpu_affinity():
    if len(os.sched_getaffinity(0)) < 4:
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    tempdir = tempfile.mkdtemp()

    def cpu_mask_from_proc_status(status):
        for l in status.split("\n"):
            parts = l.split(":")
            if parts[0] == "Cpus_allowed_list":
                return parts[1].strip()
        return ""

    def exec_and_get_affinity_mask(cid, exec_cpu_affinity=None):
        process_file = os.path.join(tempdir, "process.json")
        with open(process_file, "w") as f:
            process = {
	        "user": {
	            "uid": 0,
	            "gid": 0
	        },
                "terminal": False,
                "cwd" : "/",
	        "args": [
                    "/init",
                    "cat",
                    "/proc/self/status"
	        ]
            }
            if exec_cpu_affinity is not None:
                process["execCPUAffinity"] = exec_cpu_affinity
            json.dump(process, f)

        out = run_crun_command(["exec", "--process", process_file, cid])
        return cpu_mask_from_proc_status(out)

    try:
        with open("/proc/self/status") as f:
            current_cpu_mask = cpu_mask_from_proc_status(f.read())
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        mask = exec_and_get_affinity_mask(cid)
        if mask != current_cpu_mask:
            logger.info("current cpu mask %s != %s", mask, current_cpu_mask)
            return -1

        mask = exec_and_get_affinity_mask(cid, {"initial" : "0-1"})
        if mask != "0-1":
            logger.info("cpu mask %s != 0-1", mask)
            return -1

        mask = exec_and_get_affinity_mask(cid, {"final" : "0-2"})
        if mask != "0-2":
            logger.info("cpu mask %s != 0-2", mask)
            return -1

        mask = exec_and_get_affinity_mask(cid, {"initial" : "1", "final" : "0-3"})
        if mask != "0-3":
            logger.info("cpu mask %s != 0-3", mask)
            return -1
        return 0
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        shutil.rmtree(tempdir)
    return 0

def test_exec_getpgrp():
    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        for terminal in [True, False]:
            if terminal and os.isatty(1) == False:
                continue
            cmdline = ["exec", "-t" if terminal else None, cid, "/init", "getpgrp"]
            out = run_crun_command([x for x in cmdline if x is not None])
            pgrp = int(out.split("\n")[0])
            if pgrp <= 0:
                logger.info("invalid pgrp, got %d", pgrp)
                return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_exec_session_keyring():
    """Test that the exec'd process does not inherit the caller's session keyring"""
    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'pause']
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        ids = []
        for _ in range(2):
            try:
                out = run_crun_command_raw(["exec", cid, "/init", "session-keyring"]).decode(errors='ignore')
            except subprocess.CalledProcessError as e:
                out = e.output.decode(errors='ignore') if e.output else ""
                if "Function not implemented" in out:
                    return (77, "keyctl not supported")
                logger.info("exec failed: %s", out)
                return -1
            if "keyctl_join is not supported" in out:
                return (77, "keyctl not supported")
            ids.append(out.strip().splitlines()[-1])
        # each exec must get its own session keyring, not the one of the caller.
        if ids[0] == ids[1]:
            logger.info("the session keyring %s was inherited from the caller", ids[0])
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_exec_help():
    out = run_crun_command(["exec", "--help"])
    if "Usage: crun [OPTION...] exec CONTAINER cmd" not in out:
        return -1

    return 0

def test_exec_error_propagation():
    """Test that exec setup errors are propagated correctly without both chdir and read pipe errors"""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        try:
            out = run_crun_command_raw(["exec", "--cwd", "/invalid/nonexistent/path", cid, "/init", "echo", "test"])
            return -1
        except subprocess.CalledProcessError as e:
            error_msg = e.output.decode('utf-8', errors='ignore')
            has_chdir_error = "chdir" in error_msg.lower() or "No such file or directory" in error_msg
            has_read_pipe_error = "read pipe failed" in error_msg

            if has_chdir_error and has_read_pipe_error:
                logger.info("exec error propagation test failed: both chdir and read pipe errors detected")
                logger.info("error message: %s", error_msg)
                return -1

            if not has_chdir_error:
                logger.info("exec error propagation test failed: expected chdir error but got: %s", error_msg)
                return -1

            return 0
    finally:
        if cid is not None:
            try:
                run_crun_command(["delete", "-f", cid])
            except Exception as cleanup_e:
                logger.info("warning: failed to cleanup container %s: %s", cid, cleanup_e)
    return 0

def test_exec_cwd():
    """Test exec with working directory option."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)
        out = run_crun_command(["exec", "--cwd", "/", cid, "/init", "cwd"])
        if "/" not in out:
            logger.info("test_exec_cwd: expected '/' in output, got: %s", out)
            return -1
        return 0
    except Exception as e:
        logger.info("test_exec_cwd failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_exec_process_json():
    """Test exec with process.json file."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    process_file = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Create a process.json file
        process_spec = {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": ["/init", "echo", "hello"],
            "env": ["PATH=/bin", "TERM=xterm"],
            "cwd": "/"
        }

        # Use a regular temp file and close it before using
        fd, process_file = tempfile.mkstemp(suffix='.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(process_spec, f)

        out = run_crun_command(["exec", "--process", process_file, cid])
        if "hello" not in out:
            logger.info("test_exec_process_json: expected 'hello' in output, got: %s", out)
            return -1
        return 0

    except Exception as e:
        logger.info("test_exec_process_json failed: %s", e)
        return -1
    finally:
        if process_file and os.path.exists(process_file):
            os.unlink(process_file)
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_exec_detach():
    """Test exec with detach option."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Run a detached exec that writes to a file
        run_crun_command(["exec", "--detach", cid, "/init", "true"])

        # If we get here without error, the test passed
        return 0

    except Exception as e:
        logger.info("test_exec_detach failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_exec_multiple():
    """Test multiple exec calls on same container."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Run multiple exec commands
        for i in range(3):
            out = run_crun_command(["exec", cid, "/init", "echo", str(i)])
            if str(i) not in out:
                logger.info("test_exec_multiple: iteration %d failed, expected '%d' in output", i, i)
                return -1

        return 0

    except Exception as e:
        logger.info("test_exec_multiple failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_exec_exit_code():
    """Test that exec returns correct exit code."""
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        # Run exec that exits with code 0
        run_crun_command(["exec", cid, "/init", "exit", "0"])

        # Run exec that exits with non-zero code
        try:
            run_crun_command_raw(["exec", cid, "/init", "exit", "42"])
            logger.info("test_exec_exit_code: expected non-zero exit but got success")
            return -1
        except subprocess.CalledProcessError as e:
            if e.returncode != 42:
                logger.info("test_exec_exit_code: expected exit code 42, got %d", e.returncode)
                return -1

        # Failures of exec itself use 255, to be told apart from the
        # exit code of the executed process.
        for args in [[cid, "/not.here"], ["no-such-container", "/init", "true"]]:
            try:
                run_crun_command_raw(["exec"] + args)
                logger.info("test_exec_exit_code: expected exec %s to fail", args)
                return -1
            except subprocess.CalledProcessError as e:
                if e.returncode != 255:
                    logger.info("test_exec_exit_code: exec %s: expected exit code 255, got %d", args, e.returncode)
                    return -1

        return 0

    except Exception as e:
        logger.info("test_exec_exit_code failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_exec_dev_null_reopened():
    """Test that exec does not pass down the /dev/null of the host."""
    if is_rootless():
        return (77, "requires root privileges")

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    # use a different mode to tell the container /dev/null apart from the host one
    conf['linux']['devices'] = [{"path": "/dev/null", "type": "c", "major": 1, "minor": 3, "fileMode": 0o640}]
    cid = None
    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        args = [get_crun_path(), "--root", get_tests_root_status(), "exec", cid, "/init", "mode", "/proc/self/fd/0"]
        out = subprocess.check_output(args, stdin=subprocess.DEVNULL, close_fds=False).decode()
        if out != "640":
            logger.info("test_exec_dev_null_reopened: expected mode '640', got '%s'", out)
            return -1

        return 0

    except Exception as e:
        logger.info("test_exec_dev_null_reopened failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])


def test_exec_oom_score_adj():
    with open("/proc/self/oom_score_adj") as f:
        current = int(f.read())
    if current > 800:
        return 77
    container_value = current + 100
    process_value = current + 200

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    conf['process']['oomScoreAdj'] = container_value
    add_all_namespaces(conf)
    cid = None
    tempdir = tempfile.mkdtemp()

    def exec_and_get_oom_score_adj(cid, oom_score_adj=None):
        process_file = os.path.join(tempdir, "process.json")
        with open(process_file, "w") as f:
            process = {
                "user": {
                    "uid": 0,
                    "gid": 0
                },
                "terminal": False,
                "cwd" : "/",
                "args": [
                    "/init",
                    "cat",
                    "/proc/self/oom_score_adj"
                ]
            }
            if oom_score_adj is not None:
                process["oomScoreAdj"] = oom_score_adj
            json.dump(process, f)

        return run_crun_command(["exec", "--process", process_file, cid]).strip()

    try:
        _, cid = run_and_get_output(conf, hide_stderr=True, command='run', detach=True)

        out = run_crun_command(["exec", cid, "/init", "cat", "/proc/self/oom_score_adj"]).strip()
        if out != str(container_value):
            logger.info("oom_score_adj without process file %s != %d", out, container_value)
            return -1

        out = exec_and_get_oom_score_adj(cid)
        if out != str(container_value):
            logger.info("oom_score_adj from container config %s != %d", out, container_value)
            return -1

        out = exec_and_get_oom_score_adj(cid, process_value)
        if out != str(process_value):
            logger.info("oom_score_adj from process file %s != %d", out, process_value)
            return -1
        return 0
    except Exception as e:
        logger.info("test_exec_oom_score_adj failed: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        shutil.rmtree(tempdir)

all_tests = {
    "exec" : test_exec,
    "exec-not-exists" : test_exec_not_exists,
    "exec-detach-not-exists" : test_exec_detach_not_exists,
    "exec-detach-additional-gids" : test_exec_additional_gids,
    "exec-root-netns-with-userns" : test_exec_root_netns_with_userns,
    "exec-add-capability" : test_exec_add_capability,
    "exec-add-environment_variable" : test_exec_add_env,
    "exec-set-user-with-uid-gid" : test_exec_set_user,
    "exec_add_no_new_privileges" : test_exec_no_new_privs,
    "exec_write_pid_file" : test_exec_write_pid_file,
    "exec_populate_home_env_from_process_uid" : test_exec_populate_home_env_from_process_uid,
    "exec-test-uid-tty": test_uid_tty,
    "exec-cpu-affinity": test_exec_cpu_affinity,
    "exec-getpgrp": test_exec_getpgrp,
    "exec-session-keyring": test_exec_session_keyring,
    "exec-help" : test_exec_help,
    "exec-error-propagation" : test_exec_error_propagation,
    "exec-cwd" : test_exec_cwd,
    "exec-process-json" : test_exec_process_json,
    "exec-detach" : test_exec_detach,
    "exec-multiple" : test_exec_multiple,
    "exec-exit-code" : test_exec_exit_code,
    "exec-dev-null-reopened" : test_exec_dev_null_reopened,
    "exec-oom-score-adj" : test_exec_oom_score_adj,
}

if __name__ == "__main__":
    tests_main(all_tests)
