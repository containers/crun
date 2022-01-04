#!/bin/bash

set -e
set -x

if test "$(id -u)" != 0; then
	echo "run as root"
	exit 1
fi

(
cd /crun
git clean -fdx
./autogen.sh
./configure
make -j "$(nproc)"
)

export GO111MODULE=off

# Install and run runtime-tools' validation tests
go get -d -u github.com/opencontainers/runtime-tools || true

export GOCACHE=/var/tmp/gocache
export TMPDIR=/var/tmp
export XDG_RUNTIME_DIR=/run

cd "$GOPATH/src/github.com/opencontainers/runtime-tools"
make -j "$(nproc)"

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

make localvalidation
