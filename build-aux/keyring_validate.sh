#!/bin/bash

# Validate crun.keyring.  Every key block must carry a "github=<user>"
# comment, and every (sub)key in the block must be one of the keys that
# user publishes on GitHub (https://github.com/<user>.gpg).

set -euo pipefail

root="$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")"
keyring="$root/crun.keyring"

for tool in gpg gpgconf curl awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "required tool not found: $tool" >&2
        exit 1
    fi
done

tmpdir="$(mktemp -d --tmpdir crun-keyring-validate.XXXXXX)"
export GNUPGHOME="$tmpdir/gnupg"
mkdir -m 0700 "$GNUPGHOME"
cleanup() {
    gpgconf --kill all >/dev/null 2>&1 || true
    rm -rf "$tmpdir"
}
trap cleanup EXIT

fail() {
    echo "[!] $*" >&2
    exit 1
}

# Print the fingerprints of all the (sub)keys read from stdin.
fingerprints() {
    gpg --show-keys --with-colons | awk -F: '$1 == "fpr" { print $10 }' | sort -u
}

# Split the keyring into one file per key block.
awk -v dir="$tmpdir" '
    /^-----BEGIN PGP PUBLIC KEY BLOCK-----$/ { n++; f = sprintf("%s/block%03d.asc", dir, n); in_block = 1 }
    in_block { print > f }
    /^-----END PGP PUBLIC KEY BLOCK-----$/ { in_block = 0; close(f) }
' "$keyring"

shopt -s nullglob
blocks=("$tmpdir"/block*.asc)
test ${#blocks[@]} -gt 0 || fail "no keys found in crun.keyring"

for block in "${blocks[@]}"; do
    n="$(basename "$block" .asc)"
    user="$(sed -En 's/^Comment: (.* )?github=([A-Za-z0-9-]+).*/\2/p' "$block")"
    test -n "$user" || fail "key $n in crun.keyring is missing a github= comment"

    fprs="$(fingerprints <"$block")"
    test -n "$fprs" || fail "key $n ($user) in crun.keyring is not a valid key"

    curl -sSfL --retry 5 -o "$tmpdir/$user.gpg" "https://github.com/$user.gpg"
    gh_fprs="$(fingerprints <"$tmpdir/$user.gpg" || true)"

    unknown="$(comm -23 <(echo "$fprs") <(echo "$gh_fprs"))"
    if test -n "$unknown"; then
        fail "key $n in crun.keyring has (sub)keys that are not $user's GitHub keys: ${unknown//$'\n'/ }"
    fi
    echo "[*] key $n: all (sub)keys are $user's GitHub keys" >&2
done

echo "------------------------------------------------------------"
echo "crun release managers:"
sed -En 's/^Comment: (.* )?github=([A-Za-z0-9-]+).*/ * \2/p' "$keyring" | sort -u
echo "------------------------------------------------------------"
gpg --show-keys <"$keyring"
