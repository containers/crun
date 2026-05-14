#!/bin/sh

set -e
cd /crun
./autogen.sh
./configure
make -j "$(nproc)"
