#!/bin/bash

set -e
cd /crun

git clean -fdx
./autogen.sh
./configure CFLAGS='-Wall -Wextra -Werror' CC=clang
intercept-build make

echo -e "\n\n----------------------------- clang-check -------------------------------\n\n"

git ls-files src | grep -E "\\.[c]" |                             \
        grep -v "chroot_realpath.c\|cloned_binary.c\|signals.c" | \
        xargs clang-check --analyze
