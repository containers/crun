FROM quay.io/fedora/fedora:latest

RUN dnf install -y awk golang python git automake autoconf libcap-devel \
     systemd-devel yajl-devel libseccomp-devel go-md2man \
    glibc-static python3-libmount libtool make git libunwind-devel binutils-devel xz-devel \
    libatomic clang

RUN git clone https://github.com/giuseppe/containers-fuzzing-corpus /testcases

RUN git clone --depth 1 https://github.com/google/honggfuzz.git && cd honggfuzz && make -j $(nproc) && make install PREFIX=/usr

COPY run-tests.sh /usr/local/bin

WORKDIR /crun

ENTRYPOINT /usr/local/bin/run-tests.sh
