FROM quay.io/centos/centos:stream8

RUN yum --enablerepo='*' --disablerepo='media-*' install -y make automake autoconf gettext \
    libtool gcc libcap-devel systemd-devel yajl-devel \
    libseccomp-devel python36 libtool git

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
