# crun

[![Build Status](https://travis-ci.org/containers/crun.svg?branch=master)](https://travis-ci.org/containers/crun)
[![Coverity Status](https://scan.coverity.com/projects/17787/badge.svg)](https://scan.coverity.com/projects/giuseppe-crun)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/containers/crun.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/containers/crun/alerts/)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/containers/crun.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/containers/crun/context:cpp)

A fast and low-memory footprint OCI Container Runtime fully written in C.

crun conforms to the OCI Container Runtime specifications
(https://github.com/opencontainers/runtime-spec).

## Documentation

The user documentation is available [here](crun.1.md).

## Static build

If you are looking for a static build, take a look at the instructions
[here](contrib/static-builder-x86_64/README.md).

## Why another implementation?

While most of the tools used in the Linux containers ecosystem are
written in Go, I believe C is a better fit for a lower level tool like
a container runtime.  runc, the most used implementation of the OCI
runtime specs written in Go, re-execs itself and use a module written
in C for setting up the environment before the container process
starts.

crun aims to be also usable as a library that can be easily included
in programs without requiring an external process for managing OCI
containers.

## Performance

crun is faster than runc and has a much lower memory footprint.

This is the elapsed time on my machine for running sequentially 100
containers, the containers run `/bin/true`:

|                                       | crun           | runc    | %      |
| -------------                         | -------------: | -----:  | -----: |
| 100 /bin/true (no network namespace)  | 0:05.70        | 0:10.95 | -47.9% |
| 100 /bin/true (new network namespace) | 0:06.16        | 0:11.17 | -44.8%  |

crun requires fewer resources, so it is also possible to set stricter
limits on the memory and number of PIDs allowed in the container:

```
# podman --runtime /usr/bin/runc run --rm --pids-limit 1 fedora echo it works
Error: container_linux.go:346: starting container process caused "process_linux.go:319: getting the final child's pid from pipe caused \"EOF\"": OCI runtime error

# podman --runtime /usr/bin/crun run --rm --pids-limit 1 fedora echo it works
it works

# podman --runtime /usr/bin/runc run --rm --memory 4M fedora echo it works
Error: container_linux.go:346: starting container process caused "process_linux.go:327: getting pipe fds for pid 13859 caused \"readlink /proc/13859/fd/0: no such file or directory\"": OCI runtime command not found error

# podman --runtime /usr/bin/crun run --rm --memory 4M fedora echo it works
it works
```

crun could go much lower than that, and require < 1M.  The used 4MB is
a hard limit set directly in Podman before calling the OCI runtime.

## Build

On Fedora these dependencies are required for the build:
```shell
dnf install -y make python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel \
    go-md2man glibc-static python3-libmount libtool
```

On RHEL/CentOS 8
```shell
yum --enablerepo='*' install -y make automake autoconf gettext \
    libtool gcc libcap-devel systemd-devel yajl-devel \
    libseccomp-devel python36 libtool
```
go-md2man is not available on RHEL/CentOS 8, so if you'd like to build
the man page, you also need to manually install go-md2man.  It can be
installed with:
```shell
yum --enablerepo='*' install -y golang
export GOPATH=$HOME/go
go get github.com/cpuguy83/go-md2man
export PATH=$PATH:$GOPATH/bin
```

On Ubuntu:
```shell
apt-get install -y make git gcc build-essential pkgconf libtool \
   libsystemd-dev libcap-dev libseccomp-dev libyajl-dev \
   go-md2man libtool autoconf python3 automake
```

On Alpine
```shell
apk add gcc automake autoconf libtool gettext pkgconf git make musl-dev \
    python3 libcap-dev libseccomp-dev yajl-dev argp-standalone go-md2man
```

Unless you are also building the Python bindings, Python is needed
only by libocispec to generate the C parser at build time, it won't be
used afterwards.

Once all the dependencies are installed:
```
./autogen.sh && ./configure
make
sudo make install
```
