#!/bin/env python3
# crun - OCI runtime written in C
#
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

import subprocess
import json
import re
from tests_utils import *

def is_systemd_enabled():
    return 'SYSTEMD' in get_crun_feature_string()

def is_seccomp_enabled():
    return 'SECCOMP' in get_crun_feature_string()

def get_crun_commit():
    try:
        output = subprocess.check_output([get_crun_path(), "--version"]).decode()
        commit_match = re.search(r"commit: ([\w]+)", output)

        if commit_match:
            return commit_match.group(1)
        else:
            raise ValueError("Commit information not found")

    except (subprocess.CalledProcessError, ValueError) as e:
        logger.error("Error retrieving crun commit: %s", str(e))
        return None

def check_features(expected, actual, path):
    """Check that actual has everything from expected.

    Dicts are compared recursively, ignoring extra keys in actual. Lists
    must have the same elements in any order. Anything else must be equal.
    """
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            logger.info("# Mismatch in feature: %s", path)
            logger.info("# Expected: %s", expected)
            logger.info("# Actual: %s", actual)
            return False
        for key, value in expected.items():
            if key not in actual:
                logger.info("# Missing feature: %s.%s", path, key)
                return False
            if not check_features(value, actual[key], path + "." + key):
                return False
        return True

    if isinstance(expected, list):
        ok = isinstance(actual, list) and sorted(expected) == sorted(actual)
    else:
        ok = expected == actual
    if not ok:
        logger.info("# Mismatch in feature: %s", path)
        logger.info("# Expected: %s", expected)
        logger.info("# Actual: %s", actual)
    return ok

def test_crun_features():
    try:
        output = run_crun_command(["features"])
        features = json.loads(output)
        expected_features = {
            "ociVersionMin": "1.0.0",
            "ociVersionMax": "1.1.0+dev",
            "hooks": [
                "prestart",
                "createRuntime",
                "createContainer",
                "startContainer",
                "poststart",
                "poststop"
            ],
            "linux": {
                "namespaces": [
                    "cgroup",
                    "ipc",
                    "mount",
                    "network",
                    "pid",
                    "user",
                    "uts"
                ],
                "cgroup": {
                    "v1": True,
                    "v2": True,
                },
                "seccomp": {
                    "actions": [
                        "SCMP_ACT_ALLOW",
                        "SCMP_ACT_ERRNO",
                        "SCMP_ACT_KILL",
                        "SCMP_ACT_KILL_PROCESS",
                        "SCMP_ACT_KILL_THREAD",
                        "SCMP_ACT_LOG",
                        "SCMP_ACT_NOTIFY",
                        "SCMP_ACT_TRACE",
                        "SCMP_ACT_TRAP"
                    ],
                    "operators": [
                        "SCMP_CMP_NE",
                        "SCMP_CMP_LT",
                        "SCMP_CMP_LE",
                        "SCMP_CMP_EQ",
                        "SCMP_CMP_GE",
                        "SCMP_CMP_GT",
                        "SCMP_CMP_MASKED_EQ"
                    ]
                },
                "apparmor": {
                    "enabled": True
                },
                "selinux": {
                    "enabled": True
                },
                "mountExtensions": {
                    "idmap": {
                        "enabled": True,
                    },
                }
            },
            "potentiallyUnsafeConfigAnnotations": [
                "module.wasm.image/variant",
                "io.kubernetes.cri.container-type",
                "run.oci.",
                "org.criu.",
                "krun.",
            ]
        }

        mount_options = features.get("mountOptions", [])
        for option in ["ro", "rw", "bind", "rbind", "nosuid", "nodev", "noexec", "idmap"]:
            if option not in mount_options:
                logger.info("# Missing mount option: %s", option)
                return -1

        if is_seccomp_enabled():
            expected_features["linux"]["seccomp"]["enabled"] = True
        else:
            expected_features["linux"]["seccomp"] = {"enabled": False}

        systemd_enabled = is_systemd_enabled()
        expected_features["linux"]["cgroup"]["systemd"] = systemd_enabled
        expected_features["linux"]["cgroup"]["systemdUser"] = systemd_enabled

        if not check_features(expected_features, features, "features"):
            return -1

        if "capabilities" in features.get("linux", {}):
            capabilities = features["linux"]["capabilities"]
            if not ("CAP_SYS_ADMIN" in capabilities and "CAP_KILL" in capabilities and "CAP_NET_BIND_SERVICE" in capabilities):
                return -1

        if "annotations" not in features:
            logger.info("annotations section is missing")
            return -1

        annotations = features["annotations"]
        if annotations.get("run.oci.crun.commit") != get_crun_commit():
            logger.info("wrong value for run.oci.crun.commit")
            return -1

        if annotations.get("run.oci.crun.io_uring") != "true":
            logger.info("wrong value for run.oci.crun.io_uring")
            return -1

        if ('WASM' in get_crun_feature_string()
            and annotations.get("run.oci.crun.wasm") != "true"):
            logger.info("wrong value for run.oci.crun.wasm")
            return -1

        if 'CRIU' in get_crun_feature_string():
            if annotations.get("org.opencontainers.runc.checkpoint.enabled") != "true":
                logger.info("wrong value for org.opencontainers.runc.checkpoint.enabled")
                return -1
            if annotations.get("run.oci.crun.checkpoint.enabled") != "true":
                logger.info("wrong value for run.oci.crun.checkpoint.enabled")
                return -1

        return 0

    except Exception as e:
        logger.error("Error running crun features: %s", str(e))
        return -1

all_tests = {
    "crun-features" : test_crun_features,
}

if __name__ == "__main__":
    tests_main(all_tests)
