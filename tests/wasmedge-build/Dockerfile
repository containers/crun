FROM fedora:rawhide
ARG WASM_EDGE_VERSION="0.11.0"

# Install the deps for building crun
RUN dnf update -y && dnf install -y make python git gcc automake autoconf libcap-devel \
		systemd-devel yajl-devel libseccomp-devel pkg-config diffutils \
		libgcrypt-devel systemd-devel yajl-devel libseccomp-devel pkg-config \
		go-md2man glibc-static python3-libmount libtool buildah podman which

# Install WasmEdge
RUN curl -sSf -o install.sh https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh
RUN bash ./install.sh -p /usr/local -v $WASM_EDGE_VERSION

# The hello_wasm contains:
# 1. The example rust application called hello, which will print something to console.
# 2. The Containerfile for building the image including hello.wasm
ADD hello_wasm /hello_wasm

# Install Rust for building wasm application
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
SHELL ["/bin/bash", "-c"]
RUN source "$HOME/.cargo/env" && \
		rustup target add wasm32-wasi && \
		cd /hello_wasm/hello && \
		cargo build --release --target wasm32-wasi && \
		cp ./target/wasm32-wasi/release/hello.wasm /hello_wasm && \
		cd / && \
		rm -rf /hello_wasm/hello

COPY run-tests.sh /usr/local/bin

ENTRYPOINT ["/usr/local/bin/run-tests.sh"]
