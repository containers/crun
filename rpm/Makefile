CWD:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

.ONESHELL:
tarball-prep:
	dnf -y install autoconf automake git-core libcap-devel libkrun-devel libseccomp-devel libtool m4 systemd-devel yajl-devel &> /dev/null
	cd "$(CWD)/..";
	git submodule update --recursive --init
	git archive --prefix=crun-latest/ -o crun-latest.tar.gz HEAD

.ONESHELL:
setup: tarball-prep
	cd "$(CWD)/..";
	./autogen.sh
	./configure --disable-silent-rules --with-libkrun

srpm: setup
	make -C ../libocispec
	make -C .. srpm
