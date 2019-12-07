FROM fedora

RUN dnf install -y git dnf-utils gcc meson ninja-build libseccomp-static libcap-static \
    make python git gcc automake autoconf libcap-devel systemd-devel yajl-devel libseccomp-devel cmake \
    go-md2man glibc-static python3-libmount libtool \
    && yum-builddep -y systemd \
    && git clone --depth 1 https://github.com/systemd/systemd.git \
    && (mkdir systemd/build; cd systemd/build; meson ..; ninja version.h; ninja libsystemd.a; cp libsystemd.a /usr/lib64) \
    && (git clone --depth=1 https://github.com/lloyd/yajl.git; cd yajl; ./configure LDFLAGS=-static; cd build; make -j $(nproc); find . -name '*.a' -exec cp \{\} /usr/lib64 \;) \
    && (cd /crun; make distclean; ./configure CFLAGS="-O3" LDFLAGS="-static-libgcc -static" LIBS="/usr/lib64/libcap.a /usr/lib64/libseccomp.a /usr/lib64/libsystemd.a /usr/lib64/libyajl_s.a"; make -j $(nproc))
