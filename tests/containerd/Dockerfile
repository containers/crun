FROM ubuntu:eoan

ENV GOPATH=/root/go
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/go/bin

RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get install -y bash golang libbtrfs-dev libnl-3-dev libnet1-dev \
            protobuf-c-compiler python-minimal libcap-dev libaio-dev \
            curl libprotobuf-c-dev libprotobuf-dev socat libseccomp-dev \
            pigz lsof make git gcc build-essential pkgconf libtool \
            libsystemd-dev libcap-dev libyajl-dev \
            go-md2man libtool autoconf python3 automake \
    && mkdir -p /root/go/src/github.com/containerd \
    && chmod 755 /root \
    && (cd /root/go/src/github.com/containerd \
        && git clone https://github.com/containerd/containerd \
        && cd containerd \
        && git reset --hard v1.3.3 \
        && make \
        && make binaries \
        && make install \
        && script/setup/install-cni \
        && script/setup/install-critools) \
    && rm -rf /bin/runc /sbin/runc /usr/sbin/runc /usr/bin/runc

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh /root/go/src/github.com/containerd/containerd
