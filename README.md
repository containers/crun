crun
==========

[![Build Status](https://travis-ci.org/giuseppe/crun.svg?branch=master)](https://travis-ci.org/giuseppe/crun)

An OCI Container Runtime written in C.

An implementation of the OCI specs
(https://github.com/opencontainers/runtime-spec) written in C.

Why another implementation?
==========

While most of the tools used in the Linux containers ecosystem are
written in Go, I believe C is a better fit for such a lower level
tool.  runC, the most used implementation of the OCI runtime specs and
that is written in Go, forks itself and use a module written in C for
setting up the environment before the container process starts.

crun aims to be usable as a library, that can be easily included in
programs without requiring an external process for managing OCI
containers.

Performance
===========

crun is slightly faster than runC.

On my machine, this is the (elapsed time) for running sequentially 100
containers that execs `/bin/true`:

|                                      | crun | runC | % |
| ------------- |-------------:| -----:| -----:|
| 100 /bin/true (no network namespace) | 0m4.449s | 0m7.514s | 40.7% |
| 100 /bin/true (new network namespace) | 0m15.850s | 0m18.986s | 16.5% |


BUILD
==========

On Fedora you will need these dependencies:
```
$ dnf install -y python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel libselinux-devel \
    glibc-static python3-libmount libtool
```

Python is needed by libocispec to generate the C parser, it won't be
used afterwards.

At this point it is enough to run:
```
$ ./autogen.sh && ./configure
$ make

```
