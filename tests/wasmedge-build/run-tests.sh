#!/bin/bash

set -e
cd /crun

git clean -fdx
./autogen.sh
./configure CFLAGS='-Wall -Wextra -Werror' --with-wasmedge
make -j "$(nproc)"
