FROM quay.io/fedora/fedora:45

# The podman package is only installed for its runtime dependencies
# (conmon, netavark, passt, catatonit etc.), the podman binaries used
# by the tests are built from source.
RUN dnf install -y awk golang python git gcc automake autoconf libcap-devel \
    systemd-devel json-c-devel libseccomp-devel go-md2man libtool make \
    podman procps-ng xz && \
    dnf builddep -y podman && \
    git clone --depth=1 https://github.com/containers/podman -b v6.1 /podman && \
    cd /podman && \
    make .install.ginkgo && cp ./bin/ginkgo /usr/local/bin && \
    make

## Change default log driver to k8s-file for tests
RUN mkdir -p /etc/containers/containers.conf.d && \
    printf '[containers]\nlog_driver = "k8s-file"\n' > /etc/containers/containers.conf.d/99-log-driver.conf
RUN useradd -M -r -s /sbin/nologin containers && \
    echo containers:200000:268435456 >> /etc/subuid && echo containers:200000:268435456 >> /etc/subgid
COPY run-tests.sh /usr/local/bin
WORKDIR /podman
ENTRYPOINT /usr/local/bin/run-tests.sh
