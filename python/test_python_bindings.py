#!/usr/bin/env python3
# crun - OCI runtime written in C
#
# Copyright (C) 2026 crun Authors
# crun is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# crun is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with crun.  If not, see <http://www.gnu.org/licenses/>.
#
# Smoke test for the Python bindings.  It does not run a container (that
# requires a privileged environment); it only exercises the parts of the
# module that must keep working so a build/link regression is caught early.
# Point PYTHONPATH at the directory holding python_crun.so before running.

import gc
import json
import sys

import python_crun


def main():
    # Spec generation must keep working (feature exercised by callers).
    spec = json.loads(python_crun.spec())
    assert spec.get("ociVersion"), "generated spec has no ociVersion"
    assert spec["process"]["args"], "generated spec has no process args"

    # Every documented entry point must be present.
    expected = [
        "load_from_file", "load_from_memory", "run", "create", "delete",
        "kill", "start", "list", "status", "update", "spec", "make_context",
        "set_verbosity", "get_verbosity",
    ]
    missing = [name for name in expected if not hasattr(python_crun, name)]
    assert not missing, "missing methods: %s" % missing

    # Verbosity constants.
    for const in ("VERBOSITY_ERROR", "VERBOSITY_WARNING", "VERBOSITY_DEBUG"):
        assert hasattr(python_crun, const), "missing constant %s" % const

    # Loading a container from the generated spec must resolve every symbol
    # the module needs (this is what caught the missing parse_json_file /
    # libcrun_container_spec exports).
    python_crun.load_from_memory(json.dumps(spec))

    # Creating and dropping a context must run the capsule destructor without
    # crashing.
    ctx = python_crun.make_context("crun-python-smoke-test")
    del ctx
    gc.collect()

    print("python bindings smoke test: OK")


if __name__ == "__main__":
    sys.exit(main())
