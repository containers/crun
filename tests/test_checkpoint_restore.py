#!/bin/env python3
# crun - OCI runtime written in C
#
# Copyright (C) 2020 Adrian Reber <areber@redhat.com>
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
import json
import os
import subprocess
import errno
import tempfile
from tests_utils import *

criu_version = 0

def _get_criu_version():
    global criu_version
    if criu_version != 0:
        return criu_version

    args = ["criu", "--version"]
    version_output = subprocess.check_output(args, close_fds=False).decode().split('\n')

    if len(version_output) < 1:
        return 0

    first_line = version_output[0].split(':')

    if len(first_line) != 2:
        return 0

    version_string = first_line[1].split('.')

    if len(version_string) < 2:
        return 0

    version = int(version_string[0]) * 10000
    version += int(version_string[1]) * 100

    if len(version_string) == 3:
        version += int(version_string[2])

    if len(version_output) > 1:
        if version_output[1].startswith('GitID'):
            version -= version % 100
            version += 100

    return version


def _get_cmdline(cid, tests_root):
    s = {}
    for _ in range(50):
        try:
            if os.path.exists(os.path.join(tests_root, 'root/%s/status' % cid)):
                s = json.loads(run_crun_command(["state", cid]))
                break
            else:
                time.sleep(0.1)
        except Exception as e:
            time.sleep(0.1)

    if len(s) == 0:
        logger.info("_get_cmdline: no state found for container %s", cid)
        return ""

    if s['status'] != "running":
        logger.info("_get_cmdline: container %s status is '%s', expected 'running'", cid, s['status'])
        return ""
    if s['id'] != cid:
        logger.info("_get_cmdline: container id mismatch: got '%s', expected '%s'", s['id'], cid)
        return ""
    with open("/proc/%s/cmdline" % s['pid'], 'r') as cmdline_fd:
        return cmdline_fd.read()
    return ""


def run_cr_test(conf, before_checkpoint_cb=None, before_restore_cb=None):
    cid = None
    cr_dir = os.path.join(get_tests_root(), 'checkpoint')
    work_dir = 'work-dir'
    try:
        logger.info("run_cr_test: starting container")
        _, cid = run_and_get_output(
            conf,
            all_dev_null=True,
            use_popen=True,
            detach=True
        )
        logger.info("run_cr_test: container started with id=%s", cid)

        first_cmdline = _get_cmdline(cid, get_tests_root())
        logger.info("run_cr_test: first_cmdline='%s'", first_cmdline)
        if first_cmdline == "":
            logger.info("run_cr_test: FAILED - first_cmdline is empty")
            return -1

        if before_checkpoint_cb is not None:
            before_checkpoint_cb()

        logger.info("run_cr_test: starting checkpoint to %s", cr_dir)
        run_crun_command([
            "checkpoint",
            "--image-path=%s" % cr_dir,
            "--work-path=%s" % work_dir,
            cid
        ])
        logger.info("run_cr_test: checkpoint completed")

        bundle = os.path.join(
            get_tests_root(),
            cid.split('-')[1]
        )
        logger.info("run_cr_test: bundle path=%s", bundle)

        if before_restore_cb is not None:
            before_restore_cb()

        logger.info("run_cr_test: starting restore from %s", cr_dir)
        run_crun_command([
            "restore",
            "-d",
            "--image-path=%s" % cr_dir,
            "--work-path=%s" % work_dir,
            "--bundle=%s" % bundle,
            cid
        ])
        logger.info("run_cr_test: restore completed")

        second_cmdline = _get_cmdline(cid, get_tests_root())
        logger.info("run_cr_test: second_cmdline='%s'", second_cmdline)
        if first_cmdline != second_cmdline:
            logger.info("run_cr_test: FAILED - cmdline mismatch: first='%s' second='%s'", first_cmdline, second_cmdline)
            return -1
        logger.info("run_cr_test: SUCCESS - cmdlines match")
    except Exception as e:
        logger.info("run_cr_test: EXCEPTION - %s", e)
        raise
    finally:
        if cid is not None:
            logger.info("run_cr_test: cleaning up container %s", cid)
            run_crun_command(["delete", "-f", cid])
    return 0


def test_cr_pre_dump():
    if is_rootless() or 'CRIU' not in get_crun_feature_string():
        return 77

    if _get_criu_version() < 31700:
        return 77

    has_pre_dump = False
    for i in run_crun_command(["checkpoint", "--help"]).split('\n'):
        if "pre-dump" in i:
            has_pre_dump = True
            break

    if not has_pre_dump:
        return 77

    def _get_pre_dump_size(cr_dir):
        size = 0
        try:
            for f in os.listdir(cr_dir):
                if os.path.isfile(os.path.join(cr_dir, f)):
                    size += os.path.getsize(os.path.join(cr_dir, f))
        except FileNotFoundError:
            return 0
        return size

    conf = base_config()
    conf['process']['args'] = [
            '/init',
            'memhog',
            '10'
    ]
    add_all_namespaces(conf)

    cid = None
    cr_dir = os.path.join(get_tests_root(), 'pre-dump')
    work_dir = 'work-dir'
    try:
        _, cid = run_and_get_output(
            conf,
            all_dev_null=True,
            use_popen=True,
            detach=True
        )

        first_cmdline = _get_cmdline(cid, get_tests_root())
        if first_cmdline == "":
            logger.info("test_cr_pre_dump: failed to get first cmdline")
            return -1

        # Let's do one pre-dump first
        run_crun_command([
            "checkpoint",
            "--pre-dump",
            "--image-path=%s" % cr_dir,
            "--work-path=%s" % work_dir,
            cid
        ])

        # Get the size of the pre-dump
        pre_dump_size = _get_pre_dump_size(cr_dir)
        if pre_dump_size == 0:
            logger.info("test_cr_pre_dump: pre-dump size is 0")
            return -1

        # Do the final dump. This dump should be much smaller.
        cr_dir = os.path.join(get_tests_root(), 'checkpoint')
        run_crun_command([
            "checkpoint",
            "--parent-path=../pre-dump",
            "--image-path=%s" % cr_dir,
            "--work-path=%s" % work_dir,
            cid
        ])

        final_dump_size = _get_pre_dump_size(cr_dir)
        if (final_dump_size > pre_dump_size):
            # If the final dump is not smaller than the pre-dump
            # something was not working as expected.
            logger.info("test_cr_pre_dump: final_dump_size (%d) > pre_dump_size (%d)",
                       final_dump_size, pre_dump_size)
            return -1

        bundle = os.path.join(
            get_tests_root(),
            cid.split('-')[1]
        )

        run_crun_command([
            "restore",
            "-d",
            "--image-path=%s" % cr_dir,
            "--bundle=%s" % bundle,
            "--work-path=%s" % work_dir,
            cid
        ])

        second_cmdline = _get_cmdline(cid, get_tests_root())
        if first_cmdline != second_cmdline:
            logger.info("test_cr_pre_dump: cmdline mismatch after restore")
            return -1

    except Exception as e:
        logger.info("test_cr_pre_dump: exception: %s", e)
        return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0


def test_cr():
    if is_rootless() or 'CRIU' not in get_crun_feature_string():
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    return run_cr_test(conf)


def test_cr_with_ext_ns():
    if is_rootless() or 'CRIU' not in get_crun_feature_string():
        return 77

    if _get_criu_version() < 31601:
        return 77

    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    # Remove time namespace - external time ns checkpoint/restore not supported
    conf['linux']['namespaces'] = [
        ns for ns in conf['linux']['namespaces'] if ns['type'] != 'time'
    ]

    ns_path = os.path.join('/proc', str(os.getpid()), 'ns')
    for ns in conf['linux']['namespaces']:
        if ns['type'] == 'pid':
            ns.update({'path': os.path.join(ns_path, 'pid')})
        if ns['type'] == 'network':
            ns.update({'path': os.path.join(ns_path, 'net')})
        if ns['type'] == 'ipc':
            ns.update({'path': os.path.join(ns_path, 'ipc')})
        if ns['type'] == 'uts':
            ns.update({'path': os.path.join(ns_path, 'uts')})

    return run_cr_test(conf)


def _remove_file(filename):
    try:
        os.remove(filename)
    except OSError as e:
        # ignore "no such file" and raise other exceptions
        if e.errno != errno.ENOENT:
            raise


def _clean_up_criu_configs():
    for conf_file in ["crun.conf", "runc.conf", "annotation.conf"]:
        _remove_file(os.path.join("/etc/criu", conf_file))


def _create_criu_config(file_name, content):
    config_dir = "/etc/criu/"
    os.makedirs(config_dir, 0o755, exist_ok=True)
    with open(os.path.join(config_dir, f"{file_name}.conf"), "w") as f:
        print(content, file=f)


def _run_cr_test_with_config(config_name, log_names, extra_configs=None, annotations=None):
    """
    Helper to run CRIU tests with a configuration file.

    :param config_name: The main config to create before checkpoint/restore.
    :param log_names: Tuple of (dump_log_name, restore_log_name) for the test.
    :param extra_configs: Optional dict of extra config_name -> content to create before test.
    :param annotations: Optional dict of annotations to set in the config.
    :return: 0 on success, -1 on failure.
    """
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']

    with tempfile.TemporaryDirectory() as tmp:
        dump_log_path = os.path.join(tmp, log_names[0])
        restore_log_path = os.path.join(tmp, log_names[1])

        if extra_configs:
            for name, content in extra_configs.items():
                _create_criu_config(name, content)

        if annotations:
            conf['annotations'] = annotations

        ret = run_cr_test(
            conf,
            before_checkpoint_cb=lambda: _create_criu_config(config_name, f"log-file={dump_log_path}"),
            before_restore_cb=lambda: _create_criu_config(config_name, f"log-file={restore_log_path}")
        )
        _clean_up_criu_configs()

        if ret != 0:
            logger.info("_run_cr_test_with_config: run_cr_test returned %d", ret)
            return ret

        for path in [dump_log_path, restore_log_path]:
            if not os.path.isfile(path):
                logger.info("_run_cr_test_with_config: log file not found: %s", path)
                return -1
            if os.path.getsize(path) == 0:
                logger.info("_run_cr_test_with_config: log file is empty: %s", path)
                return -1
    return 0


def test_cr_with_runc_config():
    if is_rootless() or 'CRIU' not in get_crun_feature_string():
        return 77
    return _run_cr_test_with_config("runc", ("runc-dump.log", "runc-restore.log"))


def test_cr_with_crun_config():
    if is_rootless() or 'CRIU' not in get_crun_feature_string():
        return 77
    # runc.conf should be ignored by crun
    extra = {"runc": "log-file=test.log"}
    return _run_cr_test_with_config("crun", ("crun-dump.log", "crun-restore.log"), extra_configs=extra)


def test_cr_with_annotation_config():
    if is_rootless() or 'CRIU' not in get_crun_feature_string():
        return 77
    # Create annotation config file
    annotations = {"org.criu.config": "/etc/criu/annotation.conf"}
    _create_criu_config("annotation", f"log-file=annotation.log")
    # The following config files should be ignored by crun
    extra = {"runc": "log-file=test-runc.log", "crun": "log-file=test-crun.log"}
    return _run_cr_test_with_config("annotation", ("dump.log", "restore.log"), extra_configs=extra, annotations=annotations)


all_tests = {
    "checkpoint-restore": test_cr,
    "checkpoint-restore-ext-ns": test_cr_with_ext_ns,
    "checkpoint-restore-pre-dump": test_cr_pre_dump,
    "checkpoint-restore-with-runc-config": test_cr_with_runc_config,
    "checkpoint-restore-with-crun-config": test_cr_with_crun_config,
    "checkpoint-restore-with-annotation-config": test_cr_with_annotation_config,
}

if __name__ == "__main__":
    tests_main(all_tests)
