CWD:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

.ONESHELL:
tarball-prep:
	sudo dnf -y install git-core
	cd "$(CWD)/..";
	git submodule update --recursive --init
	git archive --prefix=crun-latest/ -o crun-latest.tar.gz HEAD

.ONESHELL:
setup: tarball-prep
	cd "$(CWD)/..";
	./autogen.sh
	./configure --disable-silent-rules --with-libkrun

srpm: setup
	make -C .. srpm
