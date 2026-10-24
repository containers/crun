FROM quay.io/fedora/fedora:latest

RUN dnf install -y git clang-tools-extra

COPY run-tests.sh /usr/local/bin
ENTRYPOINT /usr/local/bin/run-tests.sh
