FROM ubuntu:noble

ENV GOPATH=/root/go
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/go/bin

RUN apt-get update \
    && apt-get install -y bash golang-1.22 libbtrfs-dev libnl-3-dev libnet1-dev \
            protobuf-c-compiler libcap-dev libaio-dev \
            curl libprotobuf-c-dev libprotobuf-dev socat libseccomp-dev \
            pigz lsof make git gcc build-essential pkgconf libtool \
            libsystemd-dev libcap-dev libjson-c-dev \
            libtool autoconf python3 automake sudo \
    && update-alternatives --install /usr/bin/go go /usr/lib/go-1.22/bin/go 0 \
    && mkdir -p /root/go/src/github.com/containerd \
    && chmod 755 /root \
    && (cd /root/go/src/github.com/containerd \
        && git clone --depth 1 -b v2.1.1 https://github.com/containerd/containerd \
        && cd containerd \
        && make \
        && make install \
        && script/setup/install-cni \
        && script/setup/install-critools) \
    && rm -rf /bin/runc /sbin/runc /usr/sbin/runc /usr/bin/runc

COPY run-tests.sh /usr/local/bin
WORKDIR /root/go/src/github.com/containerd/containerd
ENTRYPOINT /usr/local/bin/run-tests.sh
