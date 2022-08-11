CWD:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

SUDO_CMD :=
ifneq ($(shell id -u), 0)
SUDO_CMD := sudo
endif

# Only install deps for Copr's make_srpm method to be happy. Doesn't include all
# rpm build deps
srpm-dep:
	$(SUDO_CMD) dnf -y install autoconf automake git git-archive-all \
		libcap-devel libseccomp-devel libtool m4 rpm-build systemd-devel \
		yajl-devel

.ONESHELL:
tarball-prep: srpm-dep
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

# Configure options intentionally don't match the ones used in crun.spec.in to
# minimize the dependencies required for Copr's make_srpm method.
.ONESHELL:
setup: tarball-prep
	cd "$(CWD)/..";
	./autogen.sh
	./configure --disable-silent-rules

.ONESHELL:
srpm: setup
	cd "$(CWD)/..";
	make libocispec
	make srpm
