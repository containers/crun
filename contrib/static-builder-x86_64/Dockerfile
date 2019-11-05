FROM registry.fedoraproject.org/fedora:latest AS base
RUN dnf install -y git dnf-utils gcc meson ninja-build libcap-static \
    make python git gcc automake autoconf libcap-devel systemd-devel yajl-devel libseccomp-devel cmake \
    go-md2man glibc-static python3-libmount libtool

FROM base AS systemd
RUN mkdir /out && yum-builddep -y systemd && git clone --depth 1 https://github.com/systemd/systemd.git \
    && mkdir systemd/build; cd systemd/build; meson .. --buildtype minsize --strip; ninja version.h; ninja libsystemd.a; cp libsystemd.a /out

FROM base AS yajl
RUN mkdir /out && git clone --depth=1 https://github.com/lloyd/yajl.git; cd yajl; ./configure LDFLAGS=-static; cd build; make -j $(nproc); find . -name '*.a' -exec cp \{\} /out \;

FROM base AS seccomp
RUN mkdir /out && git clone --depth=1 https://github.com/seccomp/libseccomp.git; cd libseccomp; ./autogen.sh; ./configure --enable-static; make -j $(nproc); find . -name '*.a' -exec cp \{\} /out \;

FROM base
COPY --from=systemd /out/* /usr/lib64
COPY --from=yajl /out/* /usr/lib64
COPY --from=seccomp /out/* /usr/lib64
COPY build.sh /usr/bin/build.sh
CMD /usr/bin/build.sh
