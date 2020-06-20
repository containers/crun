#!/bin/env $PYTHON
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
import json
import subprocess
import os
import shutil
import sys
from tests_utils import *

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

all_tests = {
    "start" : test_start,
    "run-twice" : test_run_twice,
}

if __name__ == "__main__":
    tests_main(all_tests)
