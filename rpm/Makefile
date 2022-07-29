CWD:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

FEDORA_VERSION=$(shell rpm --eval %{?fedora})

# libkrun only available on Fedora 37/Rawhide
ifeq ($(FEDORA_VERSION), 37)
KRUN_SUPPORT := 1
else
KRUN_SUPPORT := 0
endif

.ONESHELL:
tarball-prep:
	dnf -y install autoconf automake git git-archive-all libcap-devel libseccomp-devel libtool m4 rpm-build systemd-devel yajl-devel
ifeq ($(KRUN_SUPPORT), 1)
	dnf -y install libkrun-devel
endif
	cd "$(CWD)/..";
	git config --global --add safe.directory /crun
	git config --global --add safe.directory /crun/libocispec
	git config --global --add safe.directory /crun/libocispec/image-spec
	git config --global --add safe.directory /crun/libocispec/runtime-spec
	git config --global --add safe.directory /crun/libocispec/yajl
	git config --global --add safe.directory $(shell pwd)/libocispec
	git config --global --add safe.directory $(shell pwd)/libocispec/image-spec
	git config --global --add safe.directory $(shell pwd)/libocispec/runtime-spec
	git config --global --add safe.directory $(shell pwd)/libocispec/yajl
	git-archive-all --prefix=crun-HEAD/ --force-submodules crun-HEAD.tar.gz

.ONESHELL:
setup: tarball-prep
	cd "$(CWD)/..";
	./autogen.sh
ifeq ($(KRUN_SUPPORT), 1)
	./configure --disable-silent-rules --with-libkrun
else
	./configure --disable-silent-rules
endif

.ONESHELL:
srpm: setup
	cd "$(CWD)/..";
	make libocispec
	make srpm
