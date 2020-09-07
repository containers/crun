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
import tempfile
from tests_utils import *
import hashlib
import datetime

def test_exec():
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
        out = run_crun_command(["exec", cid, "/init", "echo", "foo"])
        if "foo" not in out:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 0

def test_exec_not_exists_helper(detach):
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)
        try:
            if detach:
                out = run_crun_command(["exec", "-d", cid, "/not.here"])
            else:
                out = run_crun_command(["exec", cid, "/not.here"])
        except Exception as e:
            return 0
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
    return 1

def test_exec_not_exists():
    return test_exec_not_exists_helper(False)

def test_exec_detach_not_exists():
    return test_exec_not_exists_helper(False)

def test_exec_additional_gids():
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)
    cid = None
    tempdir = tempfile.mkdtemp()
    try:
        _, cid = run_and_get_output(conf, command='run', detach=True)

        process_file = os.path.join(tempdir, "process.json")
        with open(process_file, "w") as f:
            json.dump({
	        "user": {
	            "uid": 0,
	            "gid": 0,
                    "additionalGids": [432]
	        },
                "terminal": False,
	        "args": [
                    "/init",
                    "groups"
	        ],
	        "env": [
	            "PATH=/bin",
	            "TERM=xterm"
	        ],
	        "cwd": "/",
	        "noNewPrivileges": True
            }, f)
        out = run_crun_command(["exec", "--process", process_file, cid])
        if "432" not in out:
            return -1
    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])
        shutil.rmtree(tempdir)
    return 0

NONKM_OK_CONF = "var/lib/krun/config"

def test_exec_non_km_payload_helper(execpath, nonkmok):
    """
    Run exec tests for krun only using a target executable that may be able to run
    without km if it is allowed.
    Arguments:
    execpath - the executable to run in the running container
    nonkmok - a list of entries that are to be placed into krun's config file describing
        what executables are allowed to be run without km's help.
    """

    # only run these tests for krun, 77 tells the test controller this test was skipped
    runtime = os.getenv("OCI_RUNTIME")
    if runtime is None:
        return 77
    if os.path.basename(runtime) != "krun":
        return 77

    # build config.json for the container
    conf = base_config()
    conf['process']['args'] = ['/init', 'pause']
    add_all_namespaces(conf)

    # create allowed nonkm executables config file
    # run_and_get_output() will copy this file into the container
    # krun will parse the file in the container
    nonkmok_file = "/tmp/nonkmok_config"
    with open(nonkmok_file, "w") as c:
        for nonkm_entry in nonkmok:
            with open(nonkm_entry[2],"rb") as f:
                bytes = f.read() # read entire file as bytes
                readable_hash = hashlib.sha256(bytes).hexdigest()
                c.write(nonkm_entry[0] + ":" + nonkm_entry[1] + ":" + readable_hash + "\n")

    # Start the container we will exec into later.
    # Then exec to a file in the container.
    cid = None
    try:
        output, cid = run_and_get_output(conf, command='run', copy_file_in=[NONKM_OK_CONF, nonkmok_file], detach=True);
        out = run_crun_command(["exec", cid, execpath, "echo", "foo"])
        if "foo" not in out:
            print(f"Didn't find foo in this output: {out}")
            return -1

    finally:
        if cid is not None:
            run_crun_command(["delete", "-f", cid])

    os.unlink(nonkmok_file)
    return 0

def test_exec_non_km_payload_simple():
    """
    Test that /sbin/init is allowed to exec into the running container without km.
    This entry in the allowed non-km executable database does not contain a regular expression.
    """
    init = os.getenv("INIT") or "tests/init"
    nonkmok = [ 
                [ "/sbin/init", "/init", init ],              # no regular expression
              ]
    return test_exec_non_km_payload_helper("/sbin/init", nonkmok)

def test_exec_non_km_payload_pattern():
    """
    Test that /init can be execed to in the container without needing km.
    This entry in the allowed non-km executable database contains a regular expression.
    """
    init = os.getenv("INIT") or "tests/init"
    nonkmok = [ 
                [ "/sbin/init|/init", "/init", init ],        # with regular expression
              ]
    return test_exec_non_km_payload_helper("/init", nonkmok)

def test_exec_non_km_payload_disallowed():
    """
    Test that /sbin/init will be execed to as a km payload because the allowed non-km executable database
    does not allow it to run alone.
    """
    init = os.getenv("INIT") or "tests/init"
    nonkmok = [ 
                [ "/init", "/init", init ],                   # no regular expression
              ]
    return test_exec_non_km_payload_helper("/sbin/init", nonkmok)
    
all_tests = {
    "exec" : test_exec,
    "exec-not-exists" : test_exec_not_exists,
    "exec-detach-not-exists" : test_exec_detach_not_exists,
    "exec-detach-additional-gids" : test_exec_additional_gids,
    "exec-non-km-payload-simple" : test_exec_non_km_payload_simple,
    "exec-non-km-payload-pattern" : test_exec_non_km_payload_pattern,
    "exec-non-km-payload-disallowed" : test_exec_non_km_payload_disallowed,
}

if __name__ == "__main__":
    tests_main(all_tests)
