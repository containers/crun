#!/bin/sh

set -e
cd /crun

# needed to silence ambiguous directory ownership error
git config --global --add safe.directory /crun
git clean -fdx
git submodule foreach --recursive git clean -fdx

cd .copr
make srpm
