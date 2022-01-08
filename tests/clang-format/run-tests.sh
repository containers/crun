#!/bin/bash

set -e

./configure
make clang-format
git diff --exit-code src
