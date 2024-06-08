FROM quay.io/centos/centos:stream8

RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-* && \
    yum --enablerepo='powertools' install -y make automake autoconf gettext \
    criu-devel libtool gcc libcap-devel systemd-devel yajl-devel \
    libseccomp-devel python36 libtool git

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
