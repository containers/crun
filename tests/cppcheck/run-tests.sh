#!/bin/bash

set -e -x

cd /crun

git config --global --add safe.directory /crun
git clean -fdx
./autogen.sh
./configure --enable-embedded-blake3

# The generated headers are needed to analyze the sources.
make -C libocispec -j "$(nproc)"

cppcheck --version
make cppcheck
