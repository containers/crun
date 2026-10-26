#!/bin/sh

set -e
cd /crun
git config --global --add safe.directory /crun
./autogen.sh
./configure --enable-embedded-blake3 --enable-werror --disable-systemd
make -j "$(nproc)"
