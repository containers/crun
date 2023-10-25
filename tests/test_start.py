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

import time
import subprocess
import os
import os.path
import threading
import socket
import json
from tests_utils import *

def test_cwd_relative():
    conf = base_config()
    conf['process']['args'] = ['./init', 'echo', 'hello']
    conf['process']['cwd'] = "/sbin"
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf)
        if "hello" not in str(out):
            return -1
    except Exception as e:
        return -1
    return 0

def test_cwd_relative_subdir():
    conf = base_config()
    conf['process']['args'] = ['sbin/init', 'echo', 'hello']
    conf['process']['cwd'] = "/"
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf)
        if "hello" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_cwd_not_exist():
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    conf['process']['cwd'] = "/doesnotexist"
    add_all_namespaces(conf)
    try:
        run_and_get_output(conf)
    except:
        return -1
    return 0

def test_cwd_absolute():
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'hello']
    conf['process']['cwd'] = "/sbin"
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf)
        if "hello" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_not_allowed_ipc_sysctl():
    if is_rootless():
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf, ipcns=False)
    conf['linux']['sysctl'] = {'fs.mqueue.queues_max' : '100'}
    cid = None
    try:
        _, cid = run_and_get_output(conf)
        sys.stderr.write("unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf, ipcns=False)
    conf['linux']['sysctl'] = {'kernel.msgmax' : '8192'}
    cid = None
    try:
        _, cid = run_and_get_output(conf)
        sys.stderr.write("unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)
    conf['linux']['sysctl'] = {'kernel.msgmax' : '8192'}
    cid = None
    try:
        _, cid = run_and_get_output(conf)
    except Exception as e:
        sys.stderr.write("setting msgmax with new ipc namespace failed\n")
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_not_allowed_net_sysctl():
    if is_rootless():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf, netns=False)
    conf['linux']['sysctl'] = {'net.ipv4.ping_group_range' : '0 0'}
    cid = None
    try:
        _, cid = run_and_get_output(conf)
        sys.stderr.write("unexpected success\n")
        return -1
    except:
        pass
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)
    conf['linux']['sysctl'] = {'net.ipv4.ping_group_range' : '0 0'}
    cid = None
    try:
        _, cid = run_and_get_output(conf)
    except Exception as e:
        sys.stderr.write("setting net.ipv4.ping_group_range with new net namespace failed\n")
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    return 0

def test_unknown_sysctl():
    if is_rootless():
        return 77

    for sysctl in ['kernel.foo', 'bar.baz', 'fs.baz']:
        conf = base_config()
        conf['process']['args'] = ['/init', 'true']
        add_all_namespaces(conf)
        conf['linux']['sysctl'] = {sysctl : 'value'}
        cid = None
        try:
            _, cid = run_and_get_output(conf)
            sys.stderr.write("unexpected success\n")
            return -1
        except:
            return 0
        finally:
            if cid is not None:
                run_crun_command(["delete", "-f", cid])
        return 0

def test_uts_sysctl():
    if is_rootless():
        return 77

    # setting kernel.hostname must always fail.
    for utsns in [True, False]:
        conf = base_config()
        conf['process']['args'] = ['/init', 'true']
        add_all_namespaces(conf, utsns=utsns)
        conf['linux']['sysctl'] = {'kernel.hostname' : 'foo'}
        cid = None
        try:
            _, cid = run_and_get_output(conf)
            sys.stderr.write("unexpected success\n")
            return -1
        except:
            return 0
        finally:
            if cid is not None:
                run_crun_command(["delete", "-f", cid])

    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf, utsns=False)
    conf['linux']['sysctl'] = {'kernel.domainname' : 'foo'}
    cid = None
    try:
        _, cid = run_and_get_output(conf)
        sys.stderr.write("unexpected success\n")
        return -1
    except:
        return 0
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    conf = base_config()
    conf['process']['args'] = ['/init', 'true']
    add_all_namespaces(conf)
    conf['linux']['sysctl'] = {'kernel.domainname' : 'foo'}
    cid = None
    try:
        _, cid = run_and_get_output(conf)
        return 0
    except:
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_start():
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'hello']
    add_all_namespaces(conf)
    cid = None
    try:
        proc, cid = run_and_get_output(conf, command='create', use_popen=True)
        for i in range(50):
            try:
                s = run_crun_command(["state", cid])
                break
            except Exception as e:
                time.sleep(0.1)

        run_crun_command(["start", cid])
        out, _ = proc.communicate()
        if "hello" not in str(out):
            return -1

        # verify that the external_descriptors are stored correctly
        path = os.path.join(get_tests_root_status(), cid, "status")
        with open(path) as f:
            status = json.load(f)
            descriptors = status["external_descriptors"]
            if not isinstance(descriptors, str):
                print("external_descriptors is not a string")
                return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_start_override_config():
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'hello']
    add_all_namespaces(conf)
    cid = None
    try:
        proc, cid = run_and_get_output(conf, command='create', use_popen=True, relative_config_path="config/config.json")
        for i in range(50):
            try:
                s = run_crun_command(["state", cid])
                break
            except Exception as e:
                time.sleep(0.1)

        run_crun_command(["start", cid])
        out, _ = proc.communicate()
        if "hello" not in str(out):
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0


def test_run_twice():
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'hi']
    add_all_namespaces(conf)
    try:
        id_container = "container-%s" % os.getpid()
        for i in range(2):
            out, cid = run_and_get_output(conf, command='run', id_container=id_container)
            if "hi" not in str(out):
                return -1
    except:
        return -1
    return 0

def test_sd_notify():
    if 'SYSTEMD' not in get_crun_feature_string():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/mountinfo']
    add_all_namespaces(conf)
    env = dict(os.environ)
    env["NOTIFY_SOCKET"] = "/run/notify/the-socket"
    try:
        out, cid = run_and_get_output(conf, env=env, command='run')
        if "/run/notify/the-socket" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_sd_notify_file():
    if 'SYSTEMD' not in get_crun_feature_string():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'ls', '/tmp/parent-dir/the-socket/']
    add_all_namespaces(conf)
    env = dict(os.environ)
    env["NOTIFY_SOCKET"] = "/tmp/parent-dir/the-socket"
    try:
        out, cid = run_and_get_output(conf, env=env, command='run')
        if "notify" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_sd_notify_env():
    if 'SYSTEMD' not in get_crun_feature_string():
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'printenv', 'NOTIFY_SOCKET']
    add_all_namespaces(conf)
    env = dict(os.environ)
    env["NOTIFY_SOCKET"] = "/tmp/parent-dir/the-socket"
    try:
        out, cid = run_and_get_output(conf, env=env, command='run')
        if "/tmp/parent-dir/the-socket/notify" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_delete_in_created_state():
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        proc, cid = run_and_get_output(conf, command='create', use_popen=True)
        proc.wait()
        run_crun_command(["delete", cid])
    except:
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_sd_notify_proxy():
    if 'SYSTEMD' not in get_crun_feature_string():
        return 77
    if is_rootless():
        return 77

    has_open_tree_status = subprocess.call([get_init_path(), "check-feature", "open_tree"])
    has_move_mount_status = subprocess.call([get_init_path(), "check-feature", "move_mount"])
    if has_open_tree_status != 0 or has_move_mount_status != 0:
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'systemd-notify', '--ready']
    add_all_namespaces(conf, cgroupns=True, userns=True)
    mappings = [
        {
            "containerID": 0,
            # + getuid() makes sure we don't accidentally run the container as the user that's running the test.
            "hostID": 8000 + os.getuid(),
            "size": 1,
        },
    ]
    conf['linux']['uidMappings'] = mappings
    conf['linux']['gidMappings'] = mappings
    env = dict(os.environ)
    with tempfile.TemporaryDirectory() as socket_dir:
        env["NOTIFY_SOCKET"] = os.path.join(socket_dir, "notify.socket")
        ready_datagram = None
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.bind(env["NOTIFY_SOCKET"])
            s.settimeout(2)
            def notify_server():
                nonlocal ready_datagram
                ready_datagram = s.recv(1024)

            notify_thread = threading.Thread(target=notify_server)
            notify_thread.start()
            try:
                run_and_get_output(conf, env=env, command='run', chown_rootfs_to=8000)
                notify_thread.join()
                if ready_datagram != b"READY=1":
                    return -1
            except:
                return -1
            finally:
                try:
                    notify_thread.join()
                except:
                    pass
            return 0

def test_empty_home():
    conf = base_config()
    conf['process']['args'] = ['/sbin/init', 'printenv', 'HOME']
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf)
        if "/" not in str(out):
            return -1
    except Exception as e:
        return -1
    return 0

def test_run_rootless_netns_with_userns():
    if not is_rootless():
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf, netns=False)
    # rootless should not be able to join the pid=1 netns
    conf['linux']['namespaces'].append({"type" : "network", "path" : "/proc/1/ns/net"})
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
    except:
        # expect a failure
        return 0
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return -1

# Following test is for a special case where crun sets LISTEN_PID=1 when nothing is specified
# to make sure that primary process is 1, this feature makes sure crun is in parity with runc.
def test_listen_pid_env():
    conf = base_config()
    conf['process']['args'] = ['/init', 'printenv', 'LISTEN_PID']
    add_all_namespaces(conf)
    env = dict(os.environ)
    env["LISTEN_FDS"] = "1"
    try:
        out, cid = run_and_get_output(conf, env=env, command='run')
        if "1" not in str(out):
            return -1
    except:
        return -1
    return 0

def test_ioprio():
    IOPRIO_CLASS_NONE = 0
    IOPRIO_CLASS_RT = 1
    IOPRIO_CLASS_BE = 2
    IOPRIO_CLASS_IDLE = 3

    IOPRIO_CLASS_SHIFT = 13
    IOPRIO_CLASS_MASK = 0x07
    IOPRIO_PRIO_MASK = (1 << IOPRIO_CLASS_SHIFT) - 1

    supported = subprocess.call([get_init_path(), "check-feature", "ioprio"])
    if supported != 0:
        return 77

    conf = base_config()
    add_all_namespaces(conf, netns=False)

    conf['process']['args'] = ['/init', 'ioprio']
    conf['process']['ioPriority'] = {
        "class": "IOPRIO_CLASS_IDLE",
        "priority": 0
    }

    cid = None
    try:
        output, cid = run_and_get_output(conf, command='run')
        value = int(output)
        if ((value >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK) != IOPRIO_CLASS_IDLE:
            print("invalid ioprio class returned")
            return 1
        if value & IOPRIO_PRIO_MASK != 0:
            print("invalid ioprio priority returned")
            return 1
        return 0
    except Exception as e:
        return 1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

all_tests = {
    "start" : test_start,
    "start-override-config" : test_start_override_config,
    "run-twice" : test_run_twice,
    "sd-notify" : test_sd_notify,
    "sd-notify-file" : test_sd_notify_file,
    "sd-notify-env" : test_sd_notify_env,
    "sd-notify-proxy": test_sd_notify_proxy,
    "listen_pid_env": test_listen_pid_env,
    "cwd-relative": test_cwd_relative,
    "cwd-relative-subdir": test_cwd_relative_subdir,
    "cwd-absolute": test_cwd_absolute,
    "cwd-not-exist" : test_cwd_not_exist,
    "empty-home": test_empty_home,
    "delete-in-created-state": test_delete_in_created_state,
    "run-rootless-netns-with-userns" : test_run_rootless_netns_with_userns,
    "not-allowed-ipc-sysctl": test_not_allowed_ipc_sysctl,
    "not-allowed-net-sysctl": test_not_allowed_net_sysctl,
    "uts-sysctl": test_uts_sysctl,
    "unknown-sysctl": test_unknown_sysctl,
    "ioprio": test_ioprio,
}

if __name__ == "__main__":
    tests_main(all_tests)
