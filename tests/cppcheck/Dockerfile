FROM quay.io/fedora/fedora:latest

RUN dnf install -y --setopt=install_weak_deps=False awk cppcheck git-core make json-c-devel 'dnf-command(builddep)' && dnf builddep -y --setopt=install_weak_deps=False --allowerasing crun

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
