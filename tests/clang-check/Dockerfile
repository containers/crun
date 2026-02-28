FROM quay.io/fedora/fedora:latest

RUN dnf install -y awk git protobuf-c protobuf-c-devel make clang-analyzer clang-tools-extra clang python3-pip glibc-static 'dnf-command(builddep)' && \
        dnf builddep -y crun && pip install scan-build

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
