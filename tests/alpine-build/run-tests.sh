#!/bin/sh

set -e
cd /crun
./autogen.sh
./configure --enable-embedded-blake3 --enable-werror --disable-systemd
make -j "$(nproc)"
