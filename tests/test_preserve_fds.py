#!/bin/env $PYTHON
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

import time
import json
import subprocess
import os
import shutil
import sys
from tests_utils import *

def test_preserve_fds_0():
    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'ls', '/proc/1/fd']
    out = run_and_get_output(conf, preserve_fds="0")
    files = [x for x in out.split('\n') if len(x) > 0 and x[0] != '.']
    if all([int(x) < 3 for x in files]):
        return 0
    return -1

def test_preserve_fds_some():
    conf = base_config()
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'ls', '/proc/1/fd']
    with open('/dev/null', 'r') as f1, open('/dev/null', 'r') as f2, open('/dev/null', 'r') as f3:
        if hasattr(os, 'set_inheritable'):
            for i in range(100):
                try:
                    os.set_inheritable(i, True)
                except:
                    pass
        out = run_and_get_output(conf, preserve_fds="100")
    files = [x for x in out.split('\n') if len(x) > 0 and x[0] != '.']
    if any([int(x) > 3 for x in files]):
        return 0
    return -1

all_tests = {
    "preserve-fds-0" : test_preserve_fds_0,
    "preserve-fds-some" : test_preserve_fds_some,
}

if __name__ == "__main__":
    tests_main(all_tests)
