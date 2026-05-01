#!/bin/sh

set -e
cd /crun

git config --global --add safe.directory /crun

git clean -fdx
./autogen.sh
./configure --enable-embedded-yajl --enable-embedded-blake3 CFLAGS='-Wall -Wextra -Werror'
make -j "$(nproc)"

make -j "$(nproc)" distcheck DISTCHECK_CONFIGURE_FLAGS="--enable-embedded-yajl --enable-embedded-blake3"

git clean -fdx
./autogen.sh
./configure --enable-embedded-yajl --enable-embedded-blake3 CFLAGS='-Wall -Wextra -Werror' --disable-systemd
make -j "$(nproc)"

make -j "$(nproc)" distcheck DISTCHECK_CONFIGURE_FLAGS="--enable-embedded-yajl --enable-embedded-blake3"
