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
import tempfile
from tests_utils import *

def test_exec():
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
        out = run_crun_command(["exec", cid, "/init", "echo", "foo"])
        if "foo" not in out:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
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
        _, cid = run_and_get_output(conf, command='run', detach=True)

        with open("/proc/net/route") as f:
            payload = f.read()
            host_routes = [i.split('\t')[0] for i in payload.split('\n')[1:]]

        out = run_crun_command(["exec", cid, "/init", "cat", "/proc/net/route"])

        container_routes = [i.split('\t')[0] for i in payload.split('\n')[1:]]

        if len(container_routes) != len(host_routes):
            sys.stderr.write("different length for the routes in the container and on the host\n")

        host_routes.sort()
        container_routes.sort()

        for i in zip(container_routes, host_routes):
            if i[0] != i[1]:
                sys.stderr.write("different network device found\n")
                return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_exec_not_exists_helper(detach):
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
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
        _, cid = run_and_get_output(conf, command='run', detach=True)

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
        _, cid = run_and_get_output(conf, command='run', detach=True)

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
    cap_unknown_dict = {"CapInh":"0000000000000000", \
                        "CapPrm":"0000000000000000", \
                        "CapEff":"0000000000000000", \
                        "CapBnd":"0000000000000000", \
                        "CapAmb":"0000000000000000"}
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
    cap_dict = {"CAP_UNKNOWN": cap_unknown_dict, \
                "CAP_KILL": cap_kill_dict, \
                "CAP_SYS_ADMIN": cap_sys_admin_dict}
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
        for cap, value in cap_dict.items():
            out = run_crun_command(["exec", "--cap", cap, cid, "/init", "cat", "/proc/self/status"])
            for i in ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']:
                conf['process']['capabilities'][i] = []
            proc_status = parse_proc_status(out)

            for i in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
                if proc_status[i] != value[i]:
                    return -1
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
    env_dict_orig = {"HOME":"/", "PATH":"/bin"}
    env_dict_new = {"HOME":"/tmp", "PATH":"/usr/bin","FOO":"BAR"}
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
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
        _, cid = run_and_get_output(conf, command='run', detach=True)
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
        _, cid = run_and_get_output(conf, command='run', detach=True)
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
        _, cid = run_and_get_output(conf, command='run', detach=True)
        pid_file = os.path.join(tempdir, cid)
        out = run_crun_command(["exec", "--pid-file", pid_file, cid, "/init", "echo", "hello"])
        if "hello" not in out:
            return -1
        if not os.path.exists(pid_file):
            return -1

        regu_cont = re.compile(r'\d{5}')
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
}

if __name__ == "__main__":
    tests_main(all_tests)
