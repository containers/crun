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
mkdir $OUTDIR

rm -f crun-*.tar*

make dist-gzip
make dist-xz

mv crun-*.tar.gz $OUTDIR
mv crun-*.tar.xz $OUTDIR

make distclean

make -C contrib/static-builder-x86_64 build-image RUNTIME=$RUNTIME
make -C contrib/static-builder-x86_64 build-crun CRUN_SOURCE=$(pwd) RUNTIME=$RUNTIME

mv crun $OUTDIR/crun-$VERSION-static-x86_64

if test x$SKIP_GPG = x; then
    for i in $OUTDIR/*; do
        gpg2 -b --armour $i
    done
fi
