#!/bin/python -Es
# crun - OCI runtime written in C
#
# Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
# libocispec is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# libocispec is distributed in the hope that it will be useful,
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
    out = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    for i in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        if proc_status[i] != "0000000000000000":
            return -1
    return 0

def test_some_caps():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    for i in ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']:
        conf['process']['capabilities'][i] = []
    out = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    for i in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']:
        if proc_status[i] != "0000000000000000":
            return -1
    return 0

def test_new_privs():
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)

    conf['process']['noNewPrivileges'] = True
    out = run_and_get_output(conf)
    proc_status = parse_proc_status(out)
    no_new_privs = proc_status['NoNewPrivs']
    if no_new_privs != "1":
        return -1

    conf['process']['noNewPrivileges'] = False
    out = run_and_get_output(conf)
    proc_status = parse_proc_status(out)
    no_new_privs = proc_status['NoNewPrivs']
    if no_new_privs != "0":
        return -1

    return 0

def helper_test_some_caps(captypes, proc_name):
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/status']
    add_all_namespaces(conf)
    conf['process']['capabilities'] = {}
    for i in captypes + ['bounding']:
        conf['process']['capabilities'][i] = ["CAP_SYS_ADMIN"]
    out = run_and_get_output(conf)
    proc_status = parse_proc_status(out)

    if proc_status[proc_name] == "0000000000000000":
        return -1
    return 0

def test_some_caps_effective():
    return helper_test_some_caps(["effective"], 'CapEff')

def test_some_caps_bounding():
    return helper_test_some_caps(["bounding"], 'CapBnd')

def test_some_caps_inheritable():
    return helper_test_some_caps(["inheritable"], 'CapInh')

def test_some_caps_ambient():
    return helper_test_some_caps(["ambient", "permitted", "inheritable"], 'CapAmb')

def test_some_caps_permitted():
    return helper_test_some_caps(["permitted"], 'CapPrm')


all_tests = {
    "no-caps" : test_no_caps,
    "new-privs" : test_new_privs,
    "some-caps-effective" : test_some_caps_effective,
    "some-caps-bounding" : test_some_caps_bounding,
    "some-caps-inheritable" : test_some_caps_inheritable,
    "some-caps-ambient" : test_some_caps_ambient,
    "some-caps-permitted" : test_some_caps_permitted
}

if __name__ == "__main__":
    tests_main(all_tests)
