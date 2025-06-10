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

from tests_utils import *

def test_limit_pid_minus_1():
    conf = base_config()
    add_all_namespaces(conf)
    if is_rootless():
        return 77
    conf['process']['args'] = ['/init', 'cat', '/dev/null']
    conf['linux']['resources'] = {"pids" : {"limit" : -1}}
    try:
        out, _ = run_and_get_output(conf)
        if len(out) == 0:
            return 0
        sys.stderr.write("# PID limit -1 test failed: expected empty output\n")
        sys.stderr.write("# actual output length: %d\n" % len(out))
        sys.stderr.write("# output: %s\n" % out[:100])
        return -1
    except Exception as e:
        sys.stderr.write("# PID limit -1 test failed with exception: %s\n" % str(e))
        return -1

def test_limit_pid_0():
    conf = base_config()
    add_all_namespaces(conf)
    if is_rootless():
        return 77
    conf['process']['args'] = ['/init', 'cat', '/dev/null']
    conf['linux']['resources'] = {"pids" : {"limit" : 0}}
    try:
        out, _ = run_and_get_output(conf)
        if len(out) == 0:
            return 0
        sys.stderr.write("# PID limit 0 test failed: expected empty output\n")
        sys.stderr.write("# actual output length: %d\n" % len(out))
        sys.stderr.write("# output: %s\n" % out[:100])
        return -1
    except Exception as e:
        sys.stderr.write("# PID limit 0 test failed with exception: %s\n" % str(e))
        return -1

def test_limit_pid_n():
    conf = base_config()
    if is_rootless():
        return 77
    add_all_namespaces(conf)
    conf['process']['args'] = ['/init', 'forkbomb', '20']
    pid_limit = 10
    conf['linux']['resources'] = {"pids" : {"limit" : pid_limit}}
    try:
        out, _ = run_and_get_output(conf)
        sys.stderr.write("# PID limit %d test failed: expected fork bomb to be limited but command succeeded\n" % pid_limit)
        sys.stderr.write("# output: %s\n" % out[:200])
        return -1
    except Exception as e:
        error_output = ""
        if hasattr(e, 'output') and e.output:
            error_output = e.output.decode('utf-8', errors='ignore')
        if "fork: Resource temporarily unavailable" in error_output:
            return 0
        sys.stderr.write("# PID limit %d test failed: expected 'fork: Resource temporarily unavailable' error\n" % pid_limit)
        sys.stderr.write("# actual error: %s\n" % str(e))
        if error_output:
            sys.stderr.write("# error output: %s\n" % error_output[:200])
        return -1

all_tests = {
    "limit-pid-minus-1" : test_limit_pid_minus_1,
    "limit-pid-0" : test_limit_pid_0,
    "limit-pid-n" : test_limit_pid_n,
}

if __name__ == "__main__":
    tests_main(all_tests)
