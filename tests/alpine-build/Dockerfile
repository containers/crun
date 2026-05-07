FROM alpine

RUN apk add gcc automake autoconf libtool gettext pkgconf git make musl-dev \
    python3 libcap-dev libseccomp-dev argp-standalone go-md2man gperf json-c-dev

COPY run-tests.sh /usr/local/bin

ENTRYPOINT /usr/local/bin/run-tests.sh
