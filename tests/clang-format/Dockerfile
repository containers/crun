FROM quay.io/fedora/fedora:latest

RUN dnf install -y --setopt=install_weak_deps=False git-core clang-tools-extra

COPY run-tests.sh /usr/local/bin
ENTRYPOINT /usr/local/bin/run-tests.sh
