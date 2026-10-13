#!/bin/bash

set -e

# Build crun with libkrun support.  Running a krun container needs libkrun,
# KVM and passt, none of which are available here, so this only makes sure the
# krun handler keeps compiling and ends up in the binary.
cd /crun

git config --global --add safe.directory /crun
git clean -fdx
./autogen.sh
./configure --enable-embedded-blake3 --enable-werror --with-libkrun
make -j "$(nproc)"

if ! ./crun --version | grep -q LIBKRUN; then
    echo "the krun handler is missing from the built crun"
    ./crun --version
    exit 1
fi
