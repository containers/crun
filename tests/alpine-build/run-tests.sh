#!/bin/sh

set -e
cd /crun
./autogen.sh
./configure --enable-embedded-blake3 CFLAGS='-Wall -Wextra -Werror' --disable-systemd
make -j "$(nproc)"
