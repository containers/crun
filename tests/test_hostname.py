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

def test_hostname():
    conf = base_config()
    conf['process']['args'] = ['/init', 'gethostname']
    conf['hostname'] = "foomachine"
    add_all_namespaces(conf)
    out, _ = run_and_get_output(conf)
    if "foomachine" not in out:
        return -1
    return 0
    
all_tests = {
    "hostname" : test_hostname,
}

if __name__ == "__main__":
    tests_main(all_tests)
