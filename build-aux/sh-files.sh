#!/bin/bash

# Run the given command with all shell scripts in the repository as arguments.
# Only files with a .sh suffix are included: the extension-less scripts in
# build-aux are imported from gnulib and are not ours to fix.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
git ls-files -z '*.sh' | xargs -0 "$@"
