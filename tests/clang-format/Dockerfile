FROM fedora:latest

RUN dnf install -y awk git make clang-tools-extra 'dnf-command(builddep)' && dnf builddep -y crun

COPY run-tests.sh /usr/local/bin
ENTRYPOINT /usr/local/bin/run-tests.sh
