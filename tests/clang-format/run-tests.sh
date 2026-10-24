#!/bin/bash

set -e -x

cd /crun

# Recent git complains that the directory is owned by someone else,
# which happens if we run it via a Dockerfile with a volume mounted.
git config --global --add safe.directory "$(pwd)"

build-aux/c-files.sh clang-format -style=file -i
git diff --ignore-submodules --exit-code
