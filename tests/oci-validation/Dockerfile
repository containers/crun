FROM fedora:latest

ENV GOPATH=/root/go
ENV PATH=/usr/bin:/usr/sbin:/root/go/bin:/usr/local/bin::/usr/local/sbin

RUN yum install -y golang python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel libselinux-devel \
    glibc-static python3-libmount libtool make npm go-md2man && \
    npm install -g tap

COPY oci-runtime-validation /usr/local/bin

ENTRYPOINT /usr/local/bin/oci-runtime-validation
