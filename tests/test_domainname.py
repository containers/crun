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

def test_domainname():
    conf = base_config()
    conf['process']['args'] = ['/init', 'getdomainname']
    conf['domainname'] = "foomachine"
    add_all_namespaces(conf)
    out, _ = run_and_get_output(conf)
    if "foomachine" not in out:
        return -1
    conf = base_config()
    conf['process']['args'] = ['/init', 'getdomainname']
    add_all_namespaces(conf, utsns=False)
    try:
        _, cid = run_and_get_output(conf)
        sys.stderr.write("unexpected success\n")
        return -1
    except:
        return 0
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    
all_tests = {
    "domainname" : test_domainname,
}

if __name__ == "__main__":
    tests_main(all_tests)
