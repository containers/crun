FROM fedora:latest

ENV GOPATH=/root/go
ENV PATH=/usr/bin:/usr/sbin:/root/go/bin:/usr/local/bin::/usr/local/sbin

RUN yum install -y golang python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel go-md2man \
    glibc-static python3-libmount libtool make podman xz nmap-ncat && \
    dnf install -y 'dnf-command(builddep)' && dnf builddep -y podman && \
    go get github.com/onsi/ginkgo/ginkgo && \
    go get github.com/onsi/gomega/... && \
    mkdir -p /root/go/src/github.com/containers && \
    chmod 755 /root && \
    (cd /root/go/src/github.com/containers && git clone -b main https://github.com/containers/podman && \
     cd podman && \
     make install.catatonit && \
     make)

## Change default log driver to k8s-file for tests
RUN sed -i 's/journald/k8s-file/g' /usr/share/containers/containers.conf
COPY run-tests.sh /usr/local/bin
WORKDIR /root/go/src/github.com/containers/podman
ENTRYPOINT /usr/local/bin/run-tests.sh
