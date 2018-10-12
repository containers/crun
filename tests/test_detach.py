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

def test_detach():
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    out, container_id = run_and_get_output(conf, detach=True)
    if out != "":
        return -1
    try:

        state = json.loads(run_crun_command(["state", container_id]))
        if state['status'] != "running":
            return -1
        if state['id'] != container_id:
            return -1
    finally:
        run_crun_command(["delete", "-f", container_id])
    return 0

all_tests = {
    "test-detach" : test_detach,
}

if __name__ == "__main__":
    tests_main(all_tests)
