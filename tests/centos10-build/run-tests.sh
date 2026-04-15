#!/bin/sh

set -e
cd /crun

git config --global --add safe.directory /crun

git clean -fdx
./autogen.sh
./configure --enable-embedded-yyjson CFLAGS='-Wall -Wextra -Werror'
make -j "$(nproc)"

make -j "$(nproc)" distcheck DISTCHECK_CONFIGURE_FLAGS="--enable-embedded-yyjson"

git clean -fdx
./autogen.sh
./configure --enable-embedded-yyjson CFLAGS='-Wall -Wextra -Werror' --disable-systemd
make -j "$(nproc)"

make -j "$(nproc)" distcheck DISTCHECK_CONFIGURE_FLAGS="--enable-embedded-yyjson"
