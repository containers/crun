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
import json
import subprocess
import os
import shutil
import sys
from tests_utils import *

def parse_proc_limits(content):
    lines = content.split("\n")
    r = {}
    mappings = {'Max open files' : "RLIMIT_NOFILE",
                'Max processes' : "RLIMIT_NPROC",
                'Max cpu time' : "RLIMIT_CPU",
                'Max pending signals' : "RLIMIT_SIGPENDING"}
    for i in lines[1:-1]:
        s = [x.strip() for x in i.split("  ") if x != ""]
        r[mappings.get(s[0], s[0])] = s
    return r

def test_rlimits():
    if os.getuid() != 0:
        return 77
    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', '/proc/self/limits']
    rlimits = [
        {"type" : "RLIMIT_SIGPENDING",
         "soft" : 100,
         "hard" : 200},
        {"type" : "RLIMIT_NPROC",
         "soft" : 50,
         "hard" : 100},
        {"type" : "RLIMIT_NOFILE",
         "soft" : 512,
         "hard" : 512},
        {"type" : "RLIMIT_CPU",
         "soft" : 2,
         "hard" : 3},
    ]
    conf['process']['rlimits'] = rlimits
    add_all_namespaces(conf)
    out, _ = run_and_get_output(conf)
    limits = parse_proc_limits(out)

    for v in rlimits:
        limit = limits.get(v['type'])
        if str(limit[1]) != str(v['soft']) or str(limit[2]) != str(v['hard']):
            sys.stderr.write("%s: %s %s\n" % (limit[0], limit[1], limit[2]))
            return -1
    return 0

all_tests = {
    "rlimits" : test_rlimits,
}

if __name__ == "__main__":
    tests_main(all_tests)
