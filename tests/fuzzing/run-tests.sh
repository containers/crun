#!/bin/bash

set -xeu

TIMEOUT=${TIMEOUT:=10}
RUN_TIME=${RUN_TIME:=600}
VERBOSITY=${VERBOSITY:=}

N_TESTS=8

SINGLE_RUN_TIME=$(( RUN_TIME / N_TESTS ))

CORPUS=${CORPUS:=/testcases}

git config --global --add safe.directory /crun
git clean -fdx
./autogen.sh
./configure --enable-embedded-yajl HFUZZ_CC_UBSAN=1 HFUZZ_CC_ASAN=1 CC=hfuzz-clang CPPFLAGS="-D FUZZER" CFLAGS="-ggdb3 -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,indirect-calls"
make -j "$(nproc)"

mkdir rootfs
mkdir random-data

function run_test {
    export FUZZING_MODE=$1
    TEST_CASE=$2

    result=$(honggfuzz --exit_upon_crash $VERBOSITY --run_time "$SINGLE_RUN_TIME" --timeout $TIMEOUT -T -i "$TEST_CASE" -- tests/tests_libcrun_fuzzer 2>&1 | tail -n 2)
    echo "$result"
    echo "$result" | grep -q crashes_count:0
}

run_test 0 $CORPUS/config-json
run_test 1 $CORPUS/config-json
run_test 2 $CORPUS/seccomp
run_test 3 $CORPUS/signals
run_test 4 $CORPUS/paths
run_test 5 random-data
run_test 6 $CORPUS/annotations
run_test 7 $CORPUS/idmapped-mounts-option
