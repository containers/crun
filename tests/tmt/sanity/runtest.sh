#!/usr/bin/env bash

set -exo pipefail

TEMPDIR=$(mktemp -d)
TESTIMG="quay.io/libpod/busybox"
CNAME="mycont-$RANDOM"

cat /etc/redhat-release
uname -r
rpm -q crun criu

crun --version
[ $? -ne 0 ] && exit 1

crun features
[ $? -ne 0 ] && exit 1

crun list
[ $? -ne 0 ] && exit 1

# create the top most bundle and rootfs directory
mkdir -p $TEMPDIR/rootfs

# export busybox via podman into the rootfs directory
podman export $(podman create $TESTIMG) | tar -C $TEMPDIR/rootfs -xvf -
[ $? -ne 0 ] && exit 1

# use existing spec
cp ./config.json $TEMPDIR
ls $TEMPDIR
cd $TEMPDIR

crun create $CNAME
[ $? -ne 0 ] && exit 1

crun list
[ $? -ne 0 ] && exit 1

crun start $CNAME
[ $? -ne 0 ] && exit 1

crun list
[ $? -ne 0 ] && exit 1

crun state $CNAME
[ $? -ne 0 ] && exit 1

crun ps $CNAME
[ $? -ne 0 ] && exit 1

ret=$(crun exec $CNAME pwd)
[ $? -ne 0 ] || [ $ret != '/' ] && exit 1

crun pause $CNAME
[ $? -ne 0 ] && exit 1

crun state $CNAME
[ $? -ne 0 ] && exit 1

crun resume $CNAME
[ $? -ne 0 ] && exit 1

crun state $CNAME
[ $? -ne 0 ] && exit 1

ret=$(crun exec $CNAME pwd)
[ $? -ne 0 ] || [ $ret != '/' ] && exit 1

crun delete --force $CNAME
[ $? -ne 0 ] && exit 1

crun list
[ $? -ne 0 ] && exit 1

crun run $CNAME &
[ $? -ne 0 ] && exit 1

crun list
[ $? -ne 0 ] && exit 1

# make sure the container is running state
sleep 2

ret=$(crun exec $CNAME echo 'ok')
[ $? -ne 0 ] || [ $ret != 'ok' ] && exit 1

crun kill $CNAME
[ $? -ne 0 ] && exit 1

exit 0
