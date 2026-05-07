#!/bin/sh

# systemd-run --scope --user become-root -a -P -S -C bash

test -e rootfs || mkdir rootfs

./configure CC=hfuzz-clang  CPPFLAGS='-D FUZZER' CFLAGS="-ggdb3"

make

honggfuzz --verifier --timeout 10 --linux_perf_instr --threads 4  -i testcases -- tests/tests_libcrun_fuzzer
