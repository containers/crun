#!/bin/bash

cd /crun

git clean -fdx
./autogen.sh
./configure CFLAGS='-Wall -Wextra -Werror' CC=clang

set -e

intercept-build make

echo -e "\n\n----------------------------- clang-check -------------------------------\n\n"

git ls-files src | egrep "\\.[c]" |                               \
        grep -v "chroot_realpath.c\|cloned_binary.c\|signals.c" | \
        xargs clang-check --analyze
