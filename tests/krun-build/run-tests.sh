#!/bin/bash

set -e

# Build crun with libkrun support.  Running a krun container needs libkrun,
# KVM and passt, none of which are available here, so this only makes sure the
# krun handler keeps compiling and ends up in the binary.
cd /crun

git config --global --add safe.directory /crun
git clean -fdx
./autogen.sh
# -Wno-error=comment: libkrun.h up to at least 1.19.0 has a "/*" inside a
# comment, which -Werror would turn into a build failure of its own.
./configure --enable-embedded-blake3 --enable-werror --with-libkrun \
    CFLAGS="-O2 -g -Wno-error=comment"
make -j "$(nproc)"

if ! ./crun --version | grep -q LIBKRUN; then
    echo "the krun handler is missing from the built crun"
    ./crun --version
    exit 1
fi
