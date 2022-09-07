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

# Test crun is used in podman
if [[ $(podman info | grep SYSTEMD) != *WASM:wasmedge* ]]; then
	echo "podman cannot find the built crun with +WASM:wasmedge"
	exit 1
fi

# Build hellowasm image
cd /hello_wasm && \
	chmod +x ./hello.wasm && \
	buildah build --annotation "module.wasm.image/variant=compat-smart" -t hellowasm-image .

# Run hello.wasm with crun
OUTPUT=$(podman run hellowasm-image:latest)
EXPECTED_OUTPUT="This is from a main function from a wasm module"
echo "$OUTPUT"
if [[ "$OUTPUT" != "$EXPECTED_OUTPUT" ]]; then
	echo "Run wasm failed. The execution result is not matched"
	exit 1
fi
