#!/bin/sh

set -e
cd /crun
./autogen.sh
./configure CFLAGS='-Wall -Wextra -Werror' --disable-systemd
make -j "$(nproc)"
