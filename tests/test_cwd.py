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

from tests_utils import *

def test_cwd():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cwd']
    conf['process']['cwd'] = "/var"
    add_all_namespaces(conf)
    out, _ = run_and_get_output(conf, hide_stderr=True)
    if "/var" not in out:
        return -1
    return 0

def test_cwd_relative():
    conf = base_config()
    conf['process']['args'] = ['./init', 'echo', 'hello']
    conf['process']['cwd'] = "/sbin"
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
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
        out, _ = run_and_get_output(conf, hide_stderr=True)
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
        run_and_get_output(conf, hide_stderr=True)
    except:
        return -1
    return 0

def test_cwd_absolute():
    conf = base_config()
    conf['process']['args'] = ['/init', 'echo', 'hello']
    conf['process']['cwd'] = "/sbin"
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf, hide_stderr=True)
        if "hello" not in str(out):
            return -1
    except:
        return -1
    return 0

all_tests = {
    "cwd" : test_cwd,
    "cwd-relative": test_cwd_relative,
    "cwd-relative-subdir": test_cwd_relative_subdir,
    "cwd-absolute": test_cwd_absolute,
    "cwd-not-exist" : test_cwd_not_exist,
}

if __name__ == "__main__":
    tests_main(all_tests)
