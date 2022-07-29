#!/bin/sh

set -e
cd /crun
# needed to silence ambiguous directory ownership error
git config --global --add safe.directory /crun
git clean -fdx

make -f .copr/Makefile srpm
make rpm
