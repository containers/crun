#!/usr/bin/env bash

set -exo pipefail

if [[ "$(id -u)" -ne 0 ]];then
    echo "Please run this script as superuser"
    exit 1
fi

cat /etc/redhat-release
rpm -q conmon containers-common crun podman podman-tests

# Run crun specific podman tests
bats -t /usr/share/podman/test/system/030-run.bats
bats -t /usr/share/podman/test/system/075-exec.bats
bats -t /usr/share/podman/test/system/280-update.bats
