#!/bin/bash

set -e
set -x

if test "$(id -u)" != 0; then
	echo "run as root"
	exit 1
fi

(
cd /crun
git config --global --add safe.directory /crun
git clean -fdx
./autogen.sh
./configure
make -j "$(nproc)"
)

# Install and run runtime-tools' validation tests
git clone --depth=1 https://github.com/opencontainers/runtime-tools
cd runtime-tools
make -j "$(nproc)" tool
make -j "$(nproc)" install

export GOCACHE=/var/tmp/gocache
export TMPDIR=/var/tmp
export XDG_RUNTIME_DIR=/run

# Skip:
# cgroup tests as they require special configurations on the host
# readonly_paths, masked_paths and seccomp timeouts or don't work on Travis
# misc_props, kill, hostname, process and pidfile are flaky.
# start - expect to not fail if the specified process doesn't exist (support process unset)
# hooks_stdin - tests are racy
# delete - both crun and runc allow to delete a container in the "created" state.
VALIDATION_TESTS=$(make print-validation-tests | tr ' ' '\n' | grep -Ev "(hooks_stdin|misc_props|start|cgroup|readonly_paths|kill|masked_paths|seccomp|process|pidfile|hostname|delete)" | tr '\n' ' ')
export VALIDATION_TESTS
export RUNTIME="/crun/crun"
export TAPTOOL=yath

# Build test binaries
make -j "$(nproc)" runtimetest validation-executables
# Run tests
make localvalidation
