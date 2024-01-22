FROM fedora:latest

ENV GOPATH=/root/go
ENV PATH=/usr/bin:/usr/sbin:/root/go/bin:/usr/local/bin::/usr/local/sbin

RUN yum install -y python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel go-md2man conntrack-tools which \
    glibc-static python3-libmount libtool make podman xz nmap-ncat jq bats \
    iproute openssl iputils socat criu-libs irqbalance && \
    dnf install -y 'dnf-command(builddep)' && dnf builddep -y podman && \
    dnf remove -y golang && \
    sudo dnf update -y && \
    curl -LO https://dl.google.com/go/go1.19.4.linux-amd64.tar.gz && \
    sudo tar -C /usr/local -xzf go1.19.4.linux-amd64.tar.gz && \
    export GOPATH=$HOME/go && \
    export GOROOT=/usr/local/go && \
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH && \
    mkdir -p /root/go/src/github.com/cri-o && \
    chmod 755 /root && \
    (cd /root/go/src/github.com/cri-o && git clone https://github.com/cri-o/cri-o && \
    cd cri-o && \
    make all test-binaries) && \
    (mkdir -p /root/go/src/github.com/containernetworking && \
    cd /root/go/src/github.com/containernetworking && \
    git clone https://github.com/containernetworking/plugins.git && \
    cd /root/go/src/github.com/containernetworking/plugins && \
    ./build_linux.sh && \
    mkdir -p /opt/cni/bin && \
    cp bin/* /opt/cni/bin/) && \
    (mkdir -p /root/go/src/github.com/kubernetes-sigs && \
    cd /root/go/src/github.com/kubernetes-sigs && \
    git clone https://github.com/kubernetes-sigs/cri-tools && \
    cd /root/go/src/github.com/kubernetes-sigs/cri-tools && \
    make && \
    cp build/bin/linux/*/crictl /usr/local/bin/)

COPY run-tests.sh /usr/local/bin
WORKDIR /root/go/src/github.com/cri-o/cri-o
ENTRYPOINT /usr/local/bin/run-tests.sh
