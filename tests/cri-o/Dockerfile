FROM fedora:latest

ENV GOPATH=/root/go
ENV PATH=/usr/bin:/usr/sbin:/root/go/bin:/usr/local/bin::/usr/local/sbin

RUN yum install -y golang python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel go-md2man conntrack-tools which \
    glibc-static python3-libmount libtool make podman xz nmap-ncat jq bats \
    iproute openssl iputils socat && \
    dnf install -y 'dnf-command(builddep)' && dnf builddep -y podman && \
    mkdir -p /root/go/src/github.com/cri-o && \
    chmod 755 /root && \
    (cd /root/go/src/github.com/cri-o && git clone https://github.com/cri-o/cri-o && \
    cd cri-o && \
    git checkout daab4d1d8431cf3af59855d3ad220e5ded5e5822 && \
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
    cp build/bin/crictl /usr/local/bin/)

COPY run-tests.sh /usr/local/bin
WORKDIR /root/go/src/github.com/cri-o/cri-o
ENTRYPOINT /usr/local/bin/run-tests.sh
