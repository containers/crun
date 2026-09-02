FROM quay.io/fedora/fedora:latest

# Install the deps for building crun with libkrun support.  The krun handler is
# only compiled when configured with --with-libkrun, so without a build like
# this one it is never compiled in CI.
RUN dnf install -y awk make python git gcc automake autoconf libcap-devel \
		systemd-devel json-c-devel libseccomp-devel pkg-config diffutils \
		go-md2man glibc-static python3-libmount libtool which libkrun-devel

COPY run-tests.sh /usr/local/bin

ENTRYPOINT ["/usr/local/bin/run-tests.sh"]
