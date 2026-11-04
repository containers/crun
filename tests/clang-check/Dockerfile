FROM quay.io/fedora/fedora:latest

RUN dnf install -y --setopt=install_weak_deps=False awk git-core protobuf-c protobuf-c-devel make clang-analyzer clang-tools-extra clang python3-pip glibc-static json-c-devel 'dnf-command(builddep)' && \
        dnf builddep -y --setopt=install_weak_deps=False crun && pip install scan-build

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
