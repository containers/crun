#!/usr/bin/env bash

set -exo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Please run this script as superuser"
    exit 1
fi

cat /etc/redhat-release
rpm -q conmon containers-common crun podman podman-tests

ROOTLESS_USER=${ROOTLESS_USER:-testuser}

TESTS=(
/usr/share/podman/test/system/030-run.bats
/usr/share/podman/test/system/060-mount.bats
/usr/share/podman/test/system/075-exec.bats
/usr/share/podman/test/system/170-run-userns.bats
/usr/share/podman/test/system/200-pod.bats
/usr/share/podman/test/system/280-update.bats
/usr/share/podman/test/system/400-unprivileged-access.bats
/usr/share/podman/test/system/420-cgroups.bats
/usr/share/podman/test/system/520-checkpoint.bats
)

# Filter out test files that do not exist in the installed version.
existing_tests=()
for t in "${TESTS[@]}"; do
    if [[ -f $t ]]; then
        existing_tests+=("$t")
    fi
done

if [[ -z $1 ]]; then
    bats -t "${existing_tests[@]}"
elif [[ $1 == "rootless" ]]; then
    if ! id "$ROOTLESS_USER" &>/dev/null; then
        useradd "$ROOTLESS_USER"
    fi
    loginctl enable-linger "$ROOTLESS_USER"
    su - "$ROOTLESS_USER" -c "bats -t ${existing_tests[*]}"
fi
