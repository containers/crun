#!/bin/env $PYTHON
# crun - OCI runtime written in C
#
# Copyright (C) 2017, 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
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

def tty_helper(fd):
    conf = base_config()
    conf['process']['args'] = ['/init', 'isatty', fd]
    conf['process']['terminal'] = True
    add_all_namespaces(conf)
    out, _ = run_and_get_output(conf)
    if "true" not in out:
        return -1
    return 0

def test_stdin_tty():
    return tty_helper("0")

def test_stdout_tty():
    return tty_helper("1")

def test_stderr_tty():
    return tty_helper("2")

def test_tty_and_detach():
    conf = base_config()
    conf['process']['args'] = ['/init', 'isatty', 0]
    conf['process']['terminal'] = True
    add_all_namespaces(conf)
    try:
        out, _ = run_and_get_output(conf, detach=True)
    except Exception as e:
        if "use --console-socket" in e.output.decode():
            return 0
    return -1
    
all_tests = {
    "test-stdin-tty" : test_stdin_tty,
    "test-stdout-tty" : test_stdout_tty,
    "test-stderr-tty" : test_stderr_tty,
    "test-detach-tty" : test_tty_and_detach,
}

if __name__ == "__main__":
    tests_main(all_tests)
