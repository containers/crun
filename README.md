# crun

[![Build Status](https://travis-ci.org/giuseppe/crun.svg?branch=master)](https://travis-ci.org/giuseppe/crun)

A fast and low-memory footprint OCI Container Runtime fully written in C.

crun conforms to the OCI Container Runtime specifications
(https://github.com/opencontainers/runtime-spec).

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

crun is slightly faster than runc and has a much lower memory
footprint.

On my machine, this is the elapsed time for running sequentially 100
containers that runs `/bin/true`:

|                                       | crun           | runc    | %      |
| -------------                         | -------------: | -----:  | -----: |
| 100 /bin/true (no network namespace)  | 0:05.70        | 0:10.95 | -47.9% |
| 100 /bin/true (new network namespace) | 0:06.16        | 0:11.17 | -44.8%  |


## Build

On Fedora these dependencies are required for the build:
```shell
dnf install -y python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel libselinux-devel \
    glibc-static python3-libmount libtool
```

On Ubuntu:
```shell
apt-get install -y git gcc build-essential pkgconf libtool \
   libsystemd-dev libcap-dev libseccomp-dev libyajl-dev libselinux1-dev
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
