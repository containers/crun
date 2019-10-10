#!/bin/sh

mkdir -p /crun/static-build

cd /crun/static-build

test -e ../configure || (cd /crun; ./autogen.sh)

../configure CRUN_LDFLAGS='-all-static' LDFLAGS="-static-libgcc -static" LIBS="/usr/lib64/libsystemd.a /usr/lib64/librt.a /usr/lib64/libpthread.a /usr/lib64/libcap.a /usr/lib64/libseccomp.a /usr/lib64/libyajl_s.a"

exec make -j $(nproc)
