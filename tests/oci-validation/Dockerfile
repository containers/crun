FROM fedora:latest

ENV GOPATH=/root/go
ENV PATH=/usr/bin:/usr/sbin:/root/go/bin:/usr/local/bin::/usr/local/sbin

RUN yum install -y golang python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel libselinux-devel \
    glibc-static python3-libmount libtool make nodejs18-npm go-md2man && \
    ln /usr/bin/node-18 /usr/bin/node && npm-18 install -g tap@16.3.10

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
