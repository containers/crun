FROM ubuntu:noble

COPY --from=docker.io/library/golang:1.26 /usr/local/go /usr/local/go

ENV GOPATH=/root/go
ENV GOTOOLCHAIN=local
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/root/go/bin

RUN apt-get update \
    && apt-get install -y bash libbtrfs-dev libnl-3-dev libnet1-dev \
            protobuf-c-compiler libcap-dev libaio-dev \
            curl libprotobuf-c-dev libprotobuf-dev socat libseccomp-dev \
            pigz lsof make git gcc build-essential pkgconf libtool \
            libsystemd-dev libcap-dev libjson-c-dev \
            libtool autoconf python3 automake sudo \
    && mkdir -p /root/go/src/github.com/containerd \
    && chmod 755 /root \
    && (cd /root/go/src/github.com/containerd \
        && git clone --depth 1 -b v2.3.7 https://github.com/containerd/containerd \
        && cd containerd \
        && make \
        && make install) \
    && rm -rf /bin/runc /sbin/runc /usr/sbin/runc /usr/bin/runc

COPY run-tests.sh /usr/local/bin
WORKDIR /root/go/src/github.com/containerd/containerd
ENTRYPOINT /usr/local/bin/run-tests.sh
