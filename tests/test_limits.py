#!/bin/env $PYTHON
# crun - OCI runtime written in C
#
# Copyright (C) 2017 Giuseppe Scrivano <giuseppe@scrivano.org>
# crun is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
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

def test_limit_pid_0():
    conf = base_config()
    add_all_namespaces(conf)
    if os.getuid() != 0:
        return 77
    conf['process']['args'] = ['/init', 'cat', '/dev/null']
    conf['linux']['resources'] = {"pids" : {"limit" : 0}}
    out, _ = run_and_get_output(conf)
    if len(out) == 0:
        return 0
    return -1

def test_limit_pid_n():
    conf = base_config()
    if os.getuid() != 0:
        return 77
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'forkbomb', '20']
    conf['linux']['resources'] = {"pids" : {"limit" : 10}}
    try:
        run_and_get_output(conf)
    except Exception as e:
        if "fork: Resource temporarily unavailable" in e.output.decode():
            return 0
    return -1

all_tests = {
    "limit-pid-0" : test_limit_pid_0,
    "limit-pid-n" : test_limit_pid_n,
}

if __name__ == "__main__":
    tests_main(all_tests)
