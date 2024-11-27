FROM fedora:latest

ENV GOPATH=/root/go
ENV PATH=/usr/bin:/usr/sbin:/root/go/bin:/usr/local/bin::/usr/local/sbin

RUN yum install -y golang python git gcc automake autoconf libcap-devel \
    systemd-devel jansson-devel libseccomp-devel libselinux-devel \
    glibc-static python3-libmount libtool make go-md2man perl-Test2-Harness

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
