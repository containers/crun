#!/bin/bash

if test "$(id -u)" != 0; then
	echo "run as root"
	exit 1
fi

set -e
(
cd /crun
./autogen.sh
./configure CFLAGS='-Wall -Wextra -Werror'
make -j "$(nproc)"
cp crun /usr/bin/runc
)

ulimit -u unlimited

export PATH=$PATH:${PWD}/bin

make RUNC_FLAVOR=crun TEST_RUNTIME=io.containerd.runc.v2 TESTFLAGS="-timeout 120m -no-criu -test.v" integration
