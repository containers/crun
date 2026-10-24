#!/bin/sh

set -e
cd /crun
git config --global --add safe.directory /crun
./autogen.sh
./configure
make -j "$(nproc)"
