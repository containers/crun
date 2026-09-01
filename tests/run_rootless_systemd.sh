#!/bin/bash
# Run the test suite rootless with the systemd cgroup manager.
#
# Rootless crun asks the systemd user manager to create the container scope,
# so this needs a systemd user session -- and it has to run inside that
# manager's own part of the cgroup tree.  Moving a process into a cgroup
# requires write access to cgroup.procs of the common ancestor of the source
# and the destination cgroup, and of the user's cgroups only user@$UID.service
# is delegated: from anywhere else, be it system.slice for a CI step or the
# session scope of a plain login, the common ancestor is owned by root and
# "crun exec" fails with EPERM.
#
# So re-execute under "systemd-run --user --scope" if we are not there yet.

set -eu

if ! systemctl --user is-active -q basic.target; then
    echo "no systemd user session for $(id -un)" >&2
    systemctl --user --no-pager status >&2 || true
    exit 1
fi

cgroup=$(cat /proc/self/cgroup)
case "$cgroup" in
*/user@*.service/*) ;;
*)
    if [ -n "${CRUN_TESTS_REEXECED-}" ]; then
        echo "still not under user@$(id -u).service: $cgroup" >&2
        exit 1
    fi
    export CRUN_TESTS_REEXECED=1
    exec systemd-run --user --scope --quiet -- "$0" "$@"
    ;;
esac

make check-systemd ASAN_OPTIONS=detect_leaks=false || {
    cat test-suite.log
    exit 1
}
