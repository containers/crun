FROM fedora

ENV GOPATH=/root/go
ENV PATH=/usr/bin:/usr/sbin:/root/go/bin:/usr/local/bin::/usr/local/sbin

RUN yum install -y golang python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel libselinux-devel \
    glibc-static python3-libmount libtool make podman xz && \
    dnf install -y 'dnf-command(builddep)' && dnf builddep -y podman && \
    go get github.com/onsi/ginkgo/ginkgo && \
    go get github.com/onsi/gomega/... && \
    mkdir -p /root/go/src/github.com/containers && \
    chmod 755 /root && \
    (cd /root/go/src/github.com/containers && git clone https://github.com/containers/libpod && \
     cd libpod && git reset --hard c86e8f180c8b0cdbd1bafe327c4671370096c45f && \
     make install.catatonit && \
     make)

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh /root/go/src/github.com/containers/libpod
