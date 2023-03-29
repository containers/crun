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
import subprocess
import os
import os.path
import threading
import socket
import json
from tests_utils import *

def test_time_namespace():
    timens_offsets = "/proc/self/timens_offsets"

    if not os.path.exists(timens_offsets):
        return 77
    if is_rootless():
        return 77

    time_offsets = {
        "monotonic": {
            "secs": 1,
            "nanosecs": 2
        },
        "boottime": {
            "secs": 3,
            "nanosecs": 4
        }
    }

    conf = base_config()
    conf['process']['args'] = ['/init', 'cat', timens_offsets]
    conf['linux']['timeOffsets'] = time_offsets
    add_all_namespaces(conf,time=True)
    try:
        out, cid = run_and_get_output(conf, command='run')

        for line in out.split("\n"):
            parts = line.split()
            if len(parts) != 3:
                continue
            if parts[0] == "monotonic":
                if parts[1] != "1":
                    return -1
                if parts[2] != "2":
                    return -1
            if parts[0] == "boottime":
                if parts[1] != "3":
                    return -1
                if parts[2] != "4":
                    return -1
        return 0
    except:
        return -1
    return 0

all_tests = {
    "time-namespace": test_time_namespace,
}

if __name__ == "__main__":
    tests_main(all_tests)
