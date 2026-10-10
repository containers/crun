FROM registry.fedoraproject.org/fedora:latest

RUN dnf install -y --setopt=install_weak_deps=False \
      autoconf automake bash ca-certificates criu-devel gcc gdb git-core \
      glibc-static gperf json-c-devel libcap-devel libseccomp-devel \
      libtool make pkgconf-pkg-config protobuf-c-devel python3 \
      python3-libmount systemd-devel \
    && dnf clean all -y

COPY . /src
WORKDIR /src

RUN git clean -fdx

RUN ./autogen.sh \
    && ./configure --enable-embedded-blake3 \
         CFLAGS="-g -fno-omit-frame-pointer" \
    && make -j"$(nproc)"
