#!/bin/bash

set -xeuo pipefail

test -e Makefile && make distclean

./autogen.sh

./configure

make -j $(nproc)

VERSION=$($(dirname $0)/git-version-gen --prefix "" .)

OUTDIR=release-$VERSION

SKIP_GPG=${SKIP_GPG:-}

rm -rf $OUTDIR
mkdir $OUTDIR

rm -f crun-*.tar*

make dist-gzip
make dist-xz

mv crun-*.tar.gz $OUTDIR
mv crun-*.tar.xz $OUTDIR

make distclean

make -C contrib/static-builder-x86_64 build-image
make -C contrib/static-builder-x86_64 build-crun CRUN_SOURCE=$(pwd)

mv static-build/crun $OUTDIR/crun-$VERSION-static-x86_64

if test x$SKIP_GPG = x; then
    for i in $OUTDIR/*; do
        gpg2 -b --armour $i
    done
fi
