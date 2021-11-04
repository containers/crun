FROM fedora:34

RUN yum install -y make clang-tools-extra 'dnf-command(builddep)' && dnf builddep -y crun
