#!/bin/sh

set -e
cd /crun

git config --global --add safe.directory /crun

git clean -fdx
./autogen.sh
./configure --enable-embedded-blake3 --enable-werror
make -j "$(nproc)"

make -j "$(nproc)" distcheck DISTCHECK_CONFIGURE_FLAGS="--enable-embedded-blake3"

git clean -fdx
./autogen.sh
./configure --enable-embedded-blake3 --enable-werror --disable-systemd
make -j "$(nproc)"

make -j "$(nproc)" distcheck
