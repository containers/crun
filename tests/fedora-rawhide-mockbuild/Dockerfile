FROM registry.fedoraproject.org/fedora:rawhide

RUN dnf install -y git-core go-md2man make python python3-libmount rpm-build

COPY run-mockbuild.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-mockbuild.sh
