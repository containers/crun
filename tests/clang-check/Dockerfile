FROM fedora:latest

RUN yum install -y make clang-tools-extra clang openssl-devel python3-pip 'dnf-command(builddep)' && \
        dnf builddep -y crun && pip install scan-build

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
