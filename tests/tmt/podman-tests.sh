#!/usr/bin/env bash

set -exo pipefail

if [[ "$(id -u)" -ne 0 ]];then
    echo "Please run this script as superuser"
    exit 1
fi

# Remove testing-farm repos if they exist because they interfere with the
# podman-next copr. The default distro repos will not be removed and can be
# used wherever relevant.
rm -f /etc/yum.repos.d/tag-repository.repo

dnf -y install bats conmon podman podman-tests
dnf -y update --allowerasing

cat /etc/redhat-release
rpm -q conmon containers-common crun podman podman-tests

# Run crun specific podman tests
bats /usr/share/podman/test/system/030-run.bats
