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

def test_pid_file():
    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'cwd', '']
    pid_file = os.path.abspath('test-pid-%s' % os.getpid())
    try:
        run_and_get_output(conf, pid_file=pid_file)
        with open(pid_file) as p:
            content = p.read()
            if len(content) > 0:
                return 0
    finally:
        os.unlink(pid_file)
    return -1

all_tests = {
    "test_pid_file" : test_pid_file,
}

if __name__ == "__main__":
    tests_main(all_tests)
