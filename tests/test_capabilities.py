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
import shutil
import sys
from tests_utils import *

def test_no_caps():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    for i in ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']:
        conf['process']['capabilities'][i] = []
    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)

    for i in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        if proc_status.get(i, '') != "0000000000000000":
            actual = proc_status.get(i, 'MISSING')
            logger.info("%s capability check failed: expected '0000000000000000', got '%s'", i, actual)
            return -1
    return 0

def test_some_caps():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    for i in ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']:
        conf['process']['capabilities'][i] = []
    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)

    for i in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        if proc_status.get(i, '') != "0000000000000000":
            actual = proc_status.get(i, 'MISSING')
            logger.info("%s capability check failed: expected '0000000000000000', got '%s'", i, actual)
            return -1
    return 0

def test_unknown_caps():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    # unknown caps must be ignored
    for i in ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']:
        conf['process']['capabilities'][i] = ['CAP_UNKNOWN', 'UNKNOWN_CAP']
    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)

    for i in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        if proc_status.get(i, '') != "0000000000000000":
            actual = proc_status.get(i, 'MISSING')
            logger.info("%s capability check failed (unknown caps should be ignored): expected '0000000000000000', got '%s'", i, actual)
            return -1
    return 0

def test_new_privs():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)

    conf['process']['noNewPrivileges'] = True
    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)
    no_new_privs = proc_status.get('NoNewPrivs', 'MISSING')
    if no_new_privs != "1":
        logger.info("noNewPrivileges=true test failed: expected '1', got '%s'", no_new_privs)
        return -1

    with open("/proc/self/status") as f:
        host_proc_status = parse_proc_status(f.read())
        host_no_new_privs = host_proc_status.get('NoNewPrivs', '0')
        # if nonewprivs is already set, it cannot be unset, so skip the
        # next test
        if host_no_new_privs == "1":
            return (77, "host already has NoNewPrivs=1")

    conf['process']['noNewPrivileges'] = False
    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)
    no_new_privs = proc_status.get('NoNewPrivs', 'MISSING')
    if no_new_privs != "0":
        logger.info("noNewPrivileges=false test failed: expected '0', got '%s'", no_new_privs)
        return -1

    return 0

def helper_test_some_caps(uid, captypes, proc_name):
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['user']['uid'] = uid
    conf['process']['capabilities'] = {}
    for i in captypes + ['bounding']:
        conf['process']['capabilities'][i] = ["CAP_SYS_ADMIN"]
    out, _ = run_and_get_output(conf, hide_stderr=True)
    proc_status = parse_proc_status(out)

    expected = "0000000000200000"
    actual = proc_status.get(proc_name, 'MISSING')
    if actual != expected:
        logger.info("%s capability check failed for uid %d with caps %s: expected '%s', got '%s'",
                        proc_name, uid, captypes, expected, actual)
        return -1
    return 0

def test_some_caps_bounding():
    return helper_test_some_caps(0, ["bounding"], 'CapBnd')

def test_some_caps_inheritable():
    return helper_test_some_caps(0, ["inheritable"], 'CapInh')

def test_some_caps_ambient():
    return helper_test_some_caps(0, ["ambient", "permitted", "inheritable"], 'CapAmb')

def test_some_caps_permitted():
    return helper_test_some_caps(0, ["permitted"], 'CapPrm')

def test_some_caps_effective_non_root():
    if is_rootless():
        return (77, "requires root privileges")
    return helper_test_some_caps(1000, ["effective", "permitted", "inheritable", "ambient"], 'CapEff')

def test_some_caps_bounding_non_root():
    if is_rootless():
        return (77, "requires root privileges")
    return helper_test_some_caps(1000, ["bounding"], 'CapBnd')

def test_some_caps_inheritable_non_root():
    if is_rootless():
        return (77, "requires root privileges")
    return helper_test_some_caps(1000, ["inheritable"], 'CapInh')

def test_some_caps_ambient_non_root():
    if is_rootless():
        return (77, "requires root privileges")
    return helper_test_some_caps(1000, ["ambient", "permitted", "inheritable"], 'CapAmb')

def test_some_caps_permitted_non_root():
    if is_rootless():
        return (77, "requires root privileges")
    return helper_test_some_caps(1000, ["ambient", "permitted", "inheritable"], 'CapPrm')


all_tests = {
    "no-caps" : test_no_caps,
    "new-privs" : test_new_privs,
    "some-caps-bounding" : test_some_caps_bounding,
    "some-caps-inheritable" : test_some_caps_inheritable,
    "some-caps-ambient" : test_some_caps_ambient,
    "some-caps-permitted" : test_some_caps_permitted,
    "some-caps-effective-non-root" : test_some_caps_effective_non_root,
    "some-caps-bounding-non-root" : test_some_caps_bounding_non_root,
    "some-caps-inheritable-non-root" : test_some_caps_inheritable_non_root,
    "some-caps-ambient-non-root" : test_some_caps_ambient_non_root,
    "some-caps-permitted-non-root" : test_some_caps_permitted_non_root,
    "unknown-caps" : test_unknown_caps,
}

if __name__ == "__main__":
    tests_main(all_tests)
