crun
==========

An OCI Container Runtime written in C.

An experimental and full of bugs implementation of the OCI specs
(https://github.com/opencontainers/runtime-spec), run at your own
risk.

If you find it useful though, and fix any of the issue that might be
present, feel free to open a PR.

BUILD
==========

On Fedora you will need these dependencies:
```
$ dnf install -y python git gcc automake autoconf libcap-devel systemd-devel yajl-devel libseccomp-devel libselinux-devel glibc-static python3-libmount

```

Python is needed by libocispec to generate the C parser, it won't be
used afterwards.

At this point it is enough to run:
```
$ ./autogen.sh && ./configure
$ make

```
