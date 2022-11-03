#!/bin/sh

set -e
cd /crun
# needed to silence ambiguous directory ownership error
git config --global --add safe.directory /crun
git clean -fdx

make -f .copr/Makefile srpm

dnf -y install 'dnf-command(copr)'
# Copr repo subject to change after discussions with wasmtime upstream
dnf -y copr enable lsm5/wasmtime
dnf -y install libkrun-devel wasmedge-devel wasmtime-c-api-devel
make rpm
