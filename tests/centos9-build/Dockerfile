FROM quay.io/centos/centos:stream9

RUN yum --enablerepo='*' --disablerepo='nfv-*' install -y make automake autoconf gettext \
    libtool gcc libcap-devel systemd-devel yajl-devel \
    libseccomp-devel python3 libtool git

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
