#!/bin/bash

cd $1

if test "$(id -u)" != 0; then
	echo "run as root"
	exit 1
fi

(cd /crun && git clean -fdx && ./autogen.sh && \
     ./configure CFLAGS='-Wall -Wextra -Werror' && make -j $(nproc) && cp crun /usr/bin/runc)

ulimit -u unlimited

export PATH=$PATH:$(pwd)/bin

make TEST_RUNTIME=io.containerd.runc.v2 TESTFLAGS="-timeout 120m" integration
