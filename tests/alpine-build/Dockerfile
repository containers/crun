FROM alpine

RUN apk add gcc automake autoconf libtool gettext pkgconf git make musl-dev \
    python3 libcap-dev libgcrypt-dev libseccomp-dev yajl-dev argp-standalone go-md2man

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
