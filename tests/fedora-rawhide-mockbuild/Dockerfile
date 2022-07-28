FROM registry.fedoraproject.org/fedora:rawhide

RUN dnf install -y git-core make rpm-build

COPY run-mockbuild.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-mockbuild.sh
