#!/bin/bash

set -xeuo pipefail

SKIP_GPG=${SKIP_GPG:-}
SKIP_CHECKS=${SKIP_CHECKS:-}

test -e Makefile && make distclean

./autogen.sh

./configure

make -j $(nproc)

VERSION=$($(dirname $0)/git-version-gen --prefix "" .)

if test x$SKIP_CHECKS = x; then
    grep $VERSION NEWS
fi

OUTDIR=release-$VERSION

rm -rf $OUTDIR
mkdir -p $OUTDIR

rm -f crun-*.tar*

make dist-gzip
make dist-xz

mv crun-*.tar.gz $OUTDIR
mv crun-*.tar.xz $OUTDIR

make distclean

RUNTIME=${RUNTIME:-podman}

mkdir -p /nix

$RUNTIME run --rm --privileged -v /nix:/nix -v ${PWD}:${PWD} -w ${PWD} nixos/nix \
    nix --print-build-logs --option cores 8 --option max-jobs 8 build --file nix/
cp ./result/bin/crun $OUTDIR/crun-$VERSION-linux-amd64

rm -rf result

$RUNTIME run --rm --privileged -v /nix:/nix -v ${PWD}:${PWD} -w ${PWD} nixos/nix \
    nix --print-build-logs --option cores 8 --option max-jobs 8 build --file nix/ --arg disableSystemd true
cp ./result/bin/crun $OUTDIR/crun-$VERSION-linux-amd64-disable-systemd

rm -rf result

if test x$SKIP_GPG = x; then
    for i in $OUTDIR/*; do
        gpg2 -b --armour $i
    done
fi
