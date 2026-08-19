#!/bin/bash

set -euo pipefail

# Download the assets of a (draft) GitHub release into a local directory so
# they can be signed with GPG before publishing.
#
# Usage: download-release.sh [VERSION]
#
# VERSION defaults to the version reported by git-version-gen (the current
# checkout).  The repository is auto-detected from the git remotes; override
# it with REPO=owner/name.  The output directory defaults to release-$VERSION
# and can be overridden with OUTDIR.

if ! command -v gh >/dev/null 2>&1; then
    echo "required tool not found: gh" >&2
    exit 1
fi

VERSION=${1:-}
if test "$VERSION" = ""; then
    VERSION="$("$(dirname "$0")/git-version-gen" --prefix "" .)"
fi

OUTDIR=${OUTDIR:-release-$VERSION}
mkdir -p "$OUTDIR"

GH_ARGS=(release download "$VERSION" --dir "$OUTDIR" --clobber)
if test "${REPO:-}" != ""; then
    GH_ARGS+=(--repo "$REPO")
fi

gh "${GH_ARGS[@]}"

echo "downloaded release $VERSION into $OUTDIR" >&2
echo "sign the assets with, e.g.:" >&2
echo "  for i in \"$OUTDIR\"/*; do gpg2 -b --armour \"\$i\"; done" >&2
