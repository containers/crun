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
        print(f"Error retrieving crun commit: {str(e)}")
        return None

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
            "mountOptions": [
                "rw",
                "rrw",
                "ro",
                "rro",
                "rdirsync",
                "rdiratime",
                "rnodev",
                "rnorelatime",
                "nodiratime",
                "rnodiratime",
                "diratime",
                "rnoatime",
                "rnomand",
                "ratime",
                "rmand",
                "mand",
                "idmap",
                "noatime",
                "nomand",
                "dirsync",
                "rnosuid",
                "atime",
                "rnoexec",
                "nodev",
                "rbind",
                "norelatime",
                "bind",
                "rnostrictatime",
                "strictatime",
                "rstrictatime",
                "rprivate",
                "rsuid",
                "remount",
                "suid",
                "nostrictatime",
                "rrelatime",
                "nosuid",
                "noexec",
                "rslave",
                "dev",
                "rdev",
                "rsync",
                "relatime",
                "sync",
                "shared",
                "rshared",
                "unbindable",
                "runbindable",
                "defaults",
                "async",
                "rasync",
                "dest-nofollow",
                "src-nofollow",
                "private",
                "tmpcopyup",
                "rexec",
                "copy-symlink",
                "exec",
                "slave"
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
                "capabilities": [
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
            "annotations": {
                "org.opencontainers.runc.checkpoint.enabled": "true",
                "run.oci.checkpoint.enabled": "true",
                "run.oci.commit": get_crun_commit(),
            },
            "potentiallyUnsafeConfigAnnotations": [
                "module.wasm.image/variant",
                "io.kubernetes.cri.container-type",
                "run.oci.",
            ]
        }

        systemd_enabled = is_systemd_enabled()
        seccomp_enabled = is_seccomp_enabled()

        if seccomp_enabled:
            expected_features["linux"]["seccomp"]["enabled"] = True

        # Check if systemd is enabled and set systemdUser accordingly
        if systemd_enabled:
            expected_features["linux"]["cgroup"]["systemd"] = True
            expected_features["linux"]["cgroup"]["systemdUser"] = True

        for key, value in expected_features.items():
            if key == "linux" and isinstance(value, dict) and "capabilities" in value:
                if "capabilities" in features.get("linux", {}):
                    capabilities = features["linux"]["capabilities"]
                    if not ("CAP_SYS_ADMIN" in capabilities and "CAP_KILL" in capabilities and "CAP_NET_BIND_SERVICE" in capabilities):
                        return -1
                continue

            if key == "annotations":
                if "annotations" not in features:
                    sys.stderr.write("# annotations section is missing\n")
                    return -1

                annotations = features["annotations"]
                if annotations.get("run.oci.crun.commit") != get_crun_commit():
                    sys.stderr.write("# wrong value for run.oci.crun.commit\n")
                    return -1

                if ('WASM' in get_crun_feature_string()
                    and annotations.get("run.oci.crun.wasm") != "true"):
                    sys.stderr.write("# wrong value for run.oci.crun.wasm\n")
                    return -1

                if 'CRIU' in get_crun_feature_string():
                    if annotations.get("org.opencontainers.runc.checkpoint.enabled") != "true":
                        sys.stderr.write("# wrong value for org.opencontainers.runc.checkpoint.enabled\n")
                        return -1
                    if annotations.get("run.oci.crun.checkpoint.enabled") != "true":
                        sys.stderr.write("# wrong value for run.oci.crun.checkpoint.enabled\n")
                        return -1
            else:
                if key not in features or sorted(features[key]) != sorted(value):
                    sys.stderr.write(f"# Mismatch in feature: {key}\n")
                    sys.stderr.write(f"# Expected: {value}\n")
                    sys.stderr.write(f"# Actual: {features.get(key)}\n")
                    return -1
        return 0

    except Exception as e:
        print("Error running crun features:", str(e))
        return -1

all_tests = {
    "crun-features" : test_crun_features,
}

if __name__ == "__main__":
    tests_main(all_tests)
