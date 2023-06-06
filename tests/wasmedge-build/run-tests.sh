#!/bin/bash

set -e

# Build crun with wasmedge support
cd /crun

git config --global --add safe.directory /crun
git clean -fdx
./autogen.sh
./configure CFLAGS='-Wall -Wextra -Werror' --with-wasmedge
make -j "$(nproc)"
make install

# Remove the installed crun to make sure the built crun is used
rm -rf /usr/bin/crun
ln -s /usr/local/bin/crun /usr/bin/crun
ln -s /usr/local/bin/crun /usr/local/bin/crun-wasm
ln -s /usr/local/bin/crun /usr/bin/crun-wasm

# Test crun is used in podman
if [[ $(podman info | grep SYSTEMD) != *WASM:wasmedge* ]]; then
	echo "podman cannot find the built crun with +WASM:wasmedge"
	exit 1
fi

# Build hellowasm image
cd /hello_wasm && \
	chmod +x ./hello.wasm && \
	buildah build --platform wasi/wasm -t hellowasm-image .

# Run hello.wasm with crun
OUTPUT=$(podman run hellowasm-image:latest)
FILE1="tmp.output"
FILE2="expected_output"
echo "$OUTPUT" > "$FILE1"
if cmp -s "$FILE1" "$FILE2"; then
	echo "Run wasm success. The execution result is exactly matched"
else
	echo "Run wasm failed. The execution result is not matched"
	exit 1
fi
