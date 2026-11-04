FROM ubuntu:26.04

RUN apt-get update -q && \
    apt-get install -q -y \
        gcc automake libtool autotools-dev \
        libseccomp-dev git make libcap-dev \
        cmake pkg-config libsystemd-dev gperf \
        libprotobuf-c-dev libblake3-dev \
        mawk libjson-c-dev python3

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
