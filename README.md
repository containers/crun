<p align="center">
  <img src="docs/crun.svg" width="450" height="450">
</p>

[![Coverity Status](https://scan.coverity.com/projects/17787/badge.svg)](https://scan.coverity.com/projects/giuseppe-crun)
[![CodeQL](https://github.com/containers/crun/workflows/CodeQL/badge.svg)](https://github.com/containers/crun/actions?query=workflow%3ACodeQL)

A fast and low-memory footprint OCI Container Runtime fully written in
C.

crun conforms to the OCI Container Runtime specifications
(<https://github.com/opencontainers/runtime-spec>).

## Documentation

The user documentation is available [here](crun.1.md).

## Why another implementation?

While most of the tools used in the Linux containers ecosystem are
written in Go, I believe C is a better fit for a lower level tool like a
container runtime. runc, the most used implementation of the OCI runtime
specs written in Go, re-execs itself and use a module written in C for
setting up the environment before the container process starts.

crun aims to be also usable as a library that can be easily included in
programs without requiring an external process for managing OCI
containers.

## Performance

crun is faster than runc and has a much lower memory footprint.

This is the elapsed time on my machine for running sequentially 100
containers, the containers run `/bin/true`:

|               |    crun |   runc |       % |
| ------------- | ------: | -----: | ------: |
| 100 /bin/true | 0:01.69 | 0:3.34 | \-49.4% |

crun requires fewer resources, so it is also possible to set stricter
limits on the memory allowed in the container:

```console
# podman --runtime /usr/bin/runc run --rm --memory 4M fedora echo it works
Error: container_linux.go:346: starting container process caused "process_linux.go:327: getting pipe fds for pid 13859 caused \"readlink /proc/13859/fd/0: no such file or directory\"": OCI runtime command not found error

# podman --runtime /usr/bin/crun run --rm --memory 4M fedora echo it works
it works
```

crun could go much lower than that, and require \< 1M. The used 4MB is a
hard limit set directly in Podman before calling the OCI runtime.

## Dependencies

These dependencies are required for the build:

### Fedora

```console
$ sudo dnf install -y make python git gcc automake autoconf libcap-devel \
    systemd-devel yajl-devel libseccomp-devel pkg-config libgcrypt-devel \
    go-md2man glibc-static python3-libmount libtool
```

### RHEL/CentOS 8

```console
$ sudo yum --enablerepo='*' --disablerepo='media-*' install -y make automake \
    autoconf gettext \
    libtool gcc libcap-devel systemd-devel yajl-devel libgcrypt-devel \
    glibc-static libseccomp-devel python36 git
```

go-md2man is not available on RHEL/CentOS 8, so if you'd like to build
the man page, you also need to manually install go-md2man. It can be
installed with:

```console
$ sudo yum --enablerepo='*' install -y golang
$ export GOPATH=$HOME/go
$ go get github.com/cpuguy83/go-md2man
$ export PATH=$PATH:$GOPATH/bin
```

### Ubuntu

```console
$ sudo apt-get install -y make git gcc build-essential pkgconf libtool \
   libsystemd-dev libprotobuf-c-dev libcap-dev libseccomp-dev libyajl-dev \
   libgcrypt20-dev go-md2man autoconf python3 automake
```

### Alpine

```console
# apk add gcc automake autoconf libtool gettext pkgconf git make musl-dev \
    python3 libcap-dev libseccomp-dev yajl-dev argp-standalone go-md2man
```

### Tumbleweed

```console
# zypper install make automake autoconf gettext libtool gcc libcap-devel \
systemd-devel libyajl-devel libseccomp-devel python3 go-md2man \
glibc-static;
```

Note that Tumbleweed requires you to specify libseccomp's header file location
as a compiler flag.

```console
# ./autogen.sh
# ./configure CFLAGS='-I/usr/include/libseccomp'
# make
```

## Build

Unless you are also building the Python bindings, Python is needed only
by libocispec to generate the C parser at build time, it won't be used
afterwards.

Once all the dependencies are installed:

```console
$ ./autogen.sh
$ ./configure
$ make
```

To install into default PREFIX (`/usr/local`):

```console
$ sudo make install
```

### Shared Libraries

The previous build instructions do not enable shared libraries, therefore you will be unable to use libcrun. If you wish to build the shared libraries you can change the previous `./configure` statement to `./configure --enable-shared`.

## Static build

It is possible to build a statically linked binary of crun by using the
officially provided
[nix](https://nixos.org/nixos/packages.html?attr=crun&channel=nixpkgs-unstable&query=crun)
package and the derivation of it [within this repository](nix/). The
builds are completely reproducible and will create a x86\_64/amd64
stripped ELF binary for [glibc](https://www.gnu.org/software/libc).

### Nix

To build the binaries by locally installing the nix package manager:

```console
$ curl -L https://nixos.org/nix/install | sh
$ git clone --recursive https://github.com/containers/crun.git && cd crun
$ nix build -f nix/
$ ./result/bin/crun --version
```

### Ansible

An [Ansible Role](https://github.com/alvistack/ansible-role-crun) is
also available to automate the installation of the above statically
linked binary on its supported OS:

```console
$ sudo su -
# mkdir -p ~/.ansible/roles
# cd ~/.ansible/roles
# git clone https://github.com/alvistack/ansible-role-crun.git crun
# cd ~/.ansible/roles/crun
# pip3 install --upgrade --ignore-installed --requirement requirements.txt
# molecule converge
# molecule verify
```
