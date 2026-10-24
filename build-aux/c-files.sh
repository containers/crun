#!/bin/bash

# Run the given command with all C sources and headers in the repository as
# arguments.  The files that were copied into the source directory, as well as
# the generated ones, are not included.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
git ls-files contrib src tests | grep -E '\.[hc]' |
    grep -v 'blake3\|chroot_realpath.c\|cloned_binary.c\|signals.c\|mount_flags.c' |
    xargs "$@"
