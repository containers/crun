FROM quay.io/centos/centos:stream9

RUN yum  --enablerepo='appstream'  --enablerepo='baseos' --enablerepo='crb' install -y make \
    automake autoconf gettext criu-devel libtool gcc libcap-devel systemd-devel yajl-devel \
    libgcrypt-devel libseccomp-devel python3 libtool git protobuf-c protobuf-c-devel

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
