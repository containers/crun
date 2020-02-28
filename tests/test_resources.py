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

def test_resources_pid_limit():
    if os.getuid() != 0:
        return 77
    conf = base_config()
    conf['linux']['resources'] = {"pids" : {"limit" : 1024}}
    add_all_namespaces(conf)

    fn = "/sys/fs/cgroup/pids/pids.max"
    if not os.path.exists("/sys/fs/cgroup/pids"):
        fn = "/sys/fs/cgroup/pids.max"
        conf['linux']['namespaces'].append({"type" : "cgroup"})

    conf['process']['args'] = ['/init', 'cat', fn]

    out, _ = run_and_get_output(conf)
    if "1024" not in out:
        return -1
    return 0

all_tests = {
    "resources-pid-limit" : test_resources_pid_limit,
}

if __name__ == "__main__":
    tests_main(all_tests)
