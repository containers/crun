#!/bin/bash

set -xeu

TIMEOUT=${TIMEOUT:=10}
RUN_TIME=${RUN_TIME:=600}
VERBOSITY=${VERBOSITY:=}

N_TESTS=10

SINGLE_RUN_TIME=$((RUN_TIME / N_TESTS))

CORPUS=${CORPUS:=/testcases}

# Upper bound on the number of crash artifacts replayed by verify_crashes.
MAX_VERIFY=${MAX_VERIFY:=200}

FUZZER=tests/tests_libcrun_fuzzer

git config --global --add safe.directory /crun
git clean -fdx
./autogen.sh
# hfuzz-clang decides whether to add the sanitizers by looking these up with
# getenv(2) as it compiles, so they have to be in the environment of the
# build.  Passed to configure instead, they only ever reached configure
# itself, and the sanitizers were silently left out of the whole build.
export HFUZZ_CC_ASAN=1 HFUZZ_CC_UBSAN=1

./configure --enable-embedded-blake3 CC=hfuzz-clang CPPFLAGS="-D FUZZER" CFLAGS="-ggdb3 -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,indirect-calls"
make -j "$(nproc)"
make -j "$(nproc)" "$FUZZER"

mkdir rootfs
mkdir random-data

function run_test {
    export FUZZING_MODE=$1
    TEST_CASE=$2

    # shellcheck disable=SC2086
    result=$(honggfuzz --exit_upon_crash $VERBOSITY --run_time "$SINGLE_RUN_TIME" --timeout "$TIMEOUT" -T -i "$TEST_CASE" -- "$FUZZER" 2>&1 | tail -n 2)
    echo "$result"
    echo "$result" | grep -q crashes_count:0
}

# Replay crash artifacts, one per process, with the sanitizers told to write
# a report for anything they catch.  A genuine memory error in crun is
# reported by ASan/UBSan, which are still live in the process that hits it.
# A container process killed after execve() has left the sanitizer runtime
# behind with the rest of its address space and produces nothing.  Fail only
# on the former.
function verify_crashes {
    local crashdir=$1
    local logdir="$crashdir/replay"
    local list ordered artifact out rc n=0 failed=0

    rm -rf "$logdir"
    mkdir -p "$logdir"

    # De-duplicate by content: honggfuzz stamps the pid and the time into the
    # names of the artifacts it cannot unwind, so the same input shows up
    # again and again under different names.
    list=$(find "$crashdir" -maxdepth 1 -type f -name '*.fuzz' -print0 |
        xargs -0 -r sha256sum | sort -u -k1,1 | cut -d' ' -f3-)

    if test -z "$list"; then
        echo "no crash artifacts for mode $FUZZING_MODE"
        return 0
    fi

    # Replay the ones honggfuzz managed to unwind first: a zero stack hash is
    # the signature of a process that died with its address space already
    # gone, which is what the noise looks like.
    ordered=$({
        grep -v '\.STACK\.0\.' <<<"$list" || true
        grep '\.STACK\.0\.' <<<"$list" || true
    } | head -n "$MAX_VERIFY")

    while read -r artifact; do
        test -n "$artifact" || continue

        n=$((n + 1))
        out="$logdir/$n"
        mkdir -p "$out"

        rc=0
        env FUZZING_MODE="$FUZZING_MODE" \
            ASAN_OPTIONS="handle_segv=1:abort_on_error=1:detect_leaks=0:log_path=$out/san" \
            UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:log_path=$out/san" \
            timeout -s KILL "$TIMEOUT" "$FUZZER" "$artifact" >"$out/output" 2>&1 || rc=$?

        # 137 is the SIGKILL from timeout(1): the replay hung, which the
        # fuzzing run reports separately as a timeout, not as a crash.
        if test "$rc" -ne 0 && test "$rc" -ne 137 && test "$rc" -ne 124; then
            echo "REPRODUCED: $artifact exited with $rc"
            failed=1
        fi

        # The sanitizers cannot always create the log file -- a report from
        # inside the container is written after pivot_root(2), where the path
        # no longer resolves -- so check the captured output as well.
        if compgen -G "$out/san.*" >/dev/null ||
            grep -qE 'ERROR: (Address|Undefined|Leak|Memory)Sanitizer|runtime error:' "$out/output"; then
            echo "REPRODUCED: $artifact, sanitizer report:"
            cat "$out"/san.* "$out/output" 2>/dev/null || true
            failed=1
        fi
    done <<<"$ordered"

    echo "mode $FUZZING_MODE: $(wc -l <<<"$list") unique artifacts, $n replayed, failed=$failed"
    test "$failed" -eq 0
}

# Modes 0 and 1 fork and run a real container, and cannot be judged by the
# crash counter honggfuzz prints.  honggfuzz attaches with
# PTRACE_O_TRACEFORK, so every process the container spawns is traced too,
# and any of them dying from a signal is recorded as a crash of the target --
# including the ones that are supposed to die: killed by the fuzzed seccomp
# profile, killed by the kernel because a fuzzed rlimit made execve() fail
# past the point of no return, or killed by the runtime itself during
# cleanup.  None of honggfuzz's filters help: the crash counter is
# incremented before the stackhash blocklist is consulted, and --verifier
# gives up on a crash it could not unwind.  So run to completion and let
# verify_crashes decide.
function run_container_test {
    export FUZZING_MODE=$1
    TEST_CASE=$2
    CRASH_DIR="crashes-$FUZZING_MODE"

    mkdir -p "$CRASH_DIR"

    # shellcheck disable=SC2086
    honggfuzz $VERBOSITY --run_time "$SINGLE_RUN_TIME" --timeout "$TIMEOUT" -T --crashdir "$CRASH_DIR" -i "$TEST_CASE" -- "$FUZZER" 2>&1 | tail -n 2

    verify_crashes "$CRASH_DIR"
}

run_container_test 0 "$CORPUS"/config-json
run_container_test 1 "$CORPUS"/config-json
run_test 2 "$CORPUS"/seccomp
run_test 3 "$CORPUS"/signals
run_test 4 "$CORPUS"/paths
run_test 5 random-data
run_test 6 "$CORPUS"/annotations
run_test 7 "$CORPUS"/idmapped-mounts-option
run_test 8 "$CORPUS"/intelrdt
run_test 9 "$CORPUS"/cpuset-ranges
