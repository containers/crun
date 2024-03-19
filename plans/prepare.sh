#!/usr/bin/env bash

set -eox pipefail

RHEL_RELEASE=$(rpm --eval '%{?rhel}')
ARCH=$(uname -m)

if [[ $RHEL_RELEASE -eq 8 ]]; then
    # EL8 has container-tools enabled by default causing installation issues
    # with podman-next copr packages
    dnf -y module disable container-tools
    # FIXME: remove this after crun is correctly built for the epel-8-*
    # targets on podman-next copr
    dnf -y install https://download.copr.fedorainfracloud.org/results/rhcontainerbot/podman-next/centos-stream+epel-next-8-$ARCH/07097739-crun/crun-1.14.4-1.20240302220834691516.main.10.g64ee22c.el8.$ARCH.rpm
fi
# Install and enable EPEL
if [[ -f /etc/centos-release ]]; then
    dnf -y install epel-release
elif [[ $RHEL_RELEASE -ge 8 ]]; then
    dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-$RHEL_RELEASE.noarch.rpm
    dnf config-manager --set-enabled epel
fi
# Install podman-next copr and set priority higher than testing-farm default
# repos
dnf -y copr enable rhcontainerbot/podman-next
dnf config-manager --save --setopt="*:rhcontainerbot:podman-next.priority=5"
