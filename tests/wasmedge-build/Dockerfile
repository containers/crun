FROM debian:bullseye-slim
ARG WASM_EDGE_VERSION="0.11.0"

RUN apt-get update && apt-get install -y make git gcc build-essential pkgconf libtool \
  libsystemd-dev libprotobuf-c-dev libcap-dev libseccomp-dev libyajl-dev \
  go-md2man autoconf python3 automake curl libc6

#ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
RUN rm /etc/ld.so.conf.d/libc.conf
RUN curl -sSf -o install.sh https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh
RUN bash ./install.sh -p /usr/local -v $WASM_EDGE_VERSION

COPY run-tests.sh /usr/local/bin

ENTRYPOINT ["/usr/local/bin/run-tests.sh"]
