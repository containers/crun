FROM quay.io/fedora/fedora:latest

RUN dnf install -y awk cppcheck git make json-c-devel 'dnf-command(builddep)' && dnf builddep -y crun

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
