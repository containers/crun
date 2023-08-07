#!/bin/bash

set -xeuo pipefail

SKIP_GPG=${SKIP_GPG:-}
SKIP_CHECKS=${SKIP_CHECKS:-}

NIX_IMAGE=${NIX_IMAGE:-nixos/nix:2.12.0}

test -e Makefile && make distclean

./autogen.sh

./configure

make -j $(nproc)

VERSION=$($(dirname $0)/git-version-gen --prefix "" .)
if test x$SKIP_CHECKS = x; then
    grep $VERSION NEWS
fi

OUTDIR=${OUTDIR:-release-$VERSION}
if test -e $OUTDIR; then
    echo "the directory $OUTDIR already exists" >&2
    exit 1
fi

mkdir -p $OUTDIR

rm -f crun-*.tar*

make dist-gzip
make dist-xz

mv crun-*.tar.gz $OUTDIR
mv crun-*.tar.xz $OUTDIR

make distclean

RUNTIME=${RUNTIME:-podman}
RUNTIME_EXTRA_ARGS=${RUNTIME_EXTRA_ARGS:-}

mkdir -p /nix

NIX_ARGS="--extra-experimental-features nix-command --print-build-logs --option cores $(nproc) --option max-jobs $(nproc)"

$RUNTIME run --rm $RUNTIME_EXTRA_ARGS --privileged -v /nix:/nix -v ${PWD}:${PWD} -w ${PWD} ${NIX_IMAGE} \
    nix $NIX_ARGS build --file nix/
cp ./result/bin/crun $OUTDIR/crun-$VERSION-linux-amd64

rm -rf result

$RUNTIME run --rm $RUNTIME_EXTRA_ARGS --privileged -v /nix:/nix -v ${PWD}:${PWD} -w ${PWD} ${NIX_IMAGE} \
    nix $NIX_ARGS build --file nix/ --arg enableSystemd false
cp ./result/bin/crun $OUTDIR/crun-$VERSION-linux-amd64-disable-systemd

rm -rf result

for ARCH in arm64 ppc64le riscv64; do
    $RUNTIME run --rm $RUNTIME_EXTRA_ARGS --privileged -v /nix:/nix -v ${PWD}:${PWD} -w ${PWD} ${NIX_IMAGE} \
        nix $NIX_ARGS build --file nix/default-${ARCH}.nix
    cp ./result/bin/crun $OUTDIR/crun-$VERSION-linux-${ARCH}

    rm -rf result

    $RUNTIME run --rm $RUNTIME_EXTRA_ARGS --privileged -v /nix:/nix -v ${PWD}:${PWD} -w ${PWD} ${NIX_IMAGE} \
        nix $NIX_ARGS build --file nix/default-${ARCH}.nix --arg enableSystemd false
    cp ./result/bin/crun $OUTDIR/crun-$VERSION-linux-${ARCH}-disable-systemd

    rm -rf result
done

if test x$SKIP_GPG = x; then
    for i in $OUTDIR/*; do
        gpg2 -b --armour $i
    done
fi
