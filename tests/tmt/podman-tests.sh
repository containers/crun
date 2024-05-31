#!/usr/bin/env bash

set -exo pipefail

if [[ "$(id -u)" -ne 0 ]];then
    echo "Please run this script as superuser"
    exit 1
fi

if [[ $1 == '' ]]; then
    echo -e "Usage: podman-tests.sh STREAM\nSTREAM can be upstream or downstream"
    exit 1
fi

STREAM=$1

CENTOS_VERSION=$(rpm --eval '%{?centos}')
RHEL_VERSION=$(rpm --eval '%{?rhel}')

# For upstream tests, we need to test with podman and other packages from the
# podman-next copr. For downstream tests (bodhi, errata), we don't need any
# additional setup
if [[ "$STREAM" == "upstream" ]]; then
    # Use CentOS Stream 10 copr target for RHEL-10 until EPEL 10 becomes
    # available
    # `rhel` macro exists on RHEL, CentOS Stream, and Fedora ELN
    # `centos` macro exists only on CentOS Stream
    if [[ -n $CENTOS_VERSION || $RHEL_VERSION -ge 10 ]]; then
        dnf -y copr enable rhcontainerbot/podman-next centos-stream-"$CENTOS_VERSION"
    else
        dnf -y copr enable rhcontainerbot/podman-next
    fi
    echo "priority=5" >> /etc/yum.repos.d/_copr:copr.fedorainfracloud.org:rhcontainerbot:podman-next.repo
fi

# Remove testing-farm repos if they exist because they interfere with the
# podman-next copr. The default distro repos will not be removed and can be
# used wherever relevant.
rm -f /etc/yum.repos.d/tag-repository.repo

# Enable EPEL on RHEL to fetch bats, currently on RHEL 9
# TODO: Switch to EPEL10 for RHEL10 once it's available
if [[ -n $RHEL_VERSION && "$RHEL_VERSION" -eq 9 ]]; then
    dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-"$RHEL_VERSION".noarch.rpm
fi

# Install test dependencies: bats and podman-tests
# Install bats from source on CentOS Stream 10 until EPEL 10 is
# available
if [[ -n $CENTOS_VERSION && $CENTOS_VERSION -eq 10 ]]; then
    BATS_VERSION=1.11.0
    curl -sLO https://github.com/bats-core/bats-core/archive/refs/tags/v$BATS_VERSION.tar.gz
    tar zxf v$BATS_VERSION.tar.gz
    pushd bats-core-$BATS_VERSION
    ./install.sh /usr
    popd
    dnf -y install podman-tests
else
    dnf -y install bats podman-tests
fi

cat /etc/redhat-release
rpm -q crun podman-tests

# Run crun specific podman tests
bats /usr/share/podman/test/system/030-run.bats
