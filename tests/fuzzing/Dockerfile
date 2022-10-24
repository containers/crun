FROM fedora:latest

RUN yum install -y golang python git automake autoconf libcap-devel \
    libgcrypt-devel systemd-devel yajl-devel libseccomp-devel go-md2man \
    glibc-static python3-libmount libtool make honggfuzz git

RUN git clone https://github.com/giuseppe/containers-fuzzing-corpus /testcases

COPY run-tests.sh /usr/local/bin

WORKDIR /crun

ENTRYPOINT /usr/local/bin/run-tests.sh
