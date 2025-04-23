#!/usr/bin/env bash

set -exo pipefail

TEMPDIR=$(mktemp -d)
TESTIMG="quay.io/libpod/busybox"
CNAME="mycont-$RANDOM"

cat /etc/redhat-release
uname -r
rpm -q crun criu

if ! crun --version; then
    exit 1
fi

if ! crun features; then
    exit 1
fi

if ! crun list; then
    exit 1
fi

# create the top most bundle and rootfs directory
mkdir -p "$TEMPDIR"/rootfs

# export busybox via podman into the rootfs directory
if ! (podman export "$(podman create $TESTIMG)" | tar -C "$TEMPDIR"/rootfs -xvf -); then
    exit 1
fi

# use existing spec
cp ./config.json "$TEMPDIR"
ls "$TEMPDIR"
cd "$TEMPDIR"

if ! crun create $CNAME; then
    exit 1
fi

if ! crun list; then
    exit 1
fi

if ! crun start $CNAME; then
    exit 1
fi

if ! crun list; then
    exit 1
fi

if ! crun state $CNAME; then
    exit 1
fi

if ! crun ps $CNAME; then
    exit 1
fi

if ! ret=$(crun exec $CNAME pwd) || [[ "$ret" != '/' ]]; then
    exit 1
fi

if ! crun pause $CNAME; then
    exit 1
fi

if ! crun state $CNAME; then
    exit 1
fi

if ! crun resume $CNAME; then
    exit 1
fi

if ! crun state $CNAME; then
    exit 1
fi

if ! ret=$(crun exec $CNAME pwd) || [[ "$ret" != '/' ]]; then
    exit 1
fi

if ! crun delete --force $CNAME; then
    exit 1
fi

if ! crun list; then
    exit 1
fi

if ! (crun run $CNAME &); then
    exit 1
fi

if ! crun list; then
    exit 1
fi

# make sure the container is running state
sleep 2

if ! ret=$(crun exec $CNAME echo 'ok') || [[ "$ret" != 'ok' ]]; then
    exit 1
fi

if ! crun kill $CNAME; then
    exit 1
fi

exit 0
