DIST_SUBDIRS = libocispec
SUBDIRS = libocispec
ACLOCAL_AMFLAGS = -I m4

WD := $(shell pwd)
# outdir is needed by the make_srpm build type on Fedora copr
# https://docs.pagure.org/copr.copr/user_documentation.html#make-srpm
outdir ?= $(WD)

RPM_OPTS ?= --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(outdir)" --define "_rpmdir $(outdir)" --define "_buildrootdir $(WD)/.build" rpm/crun.spec

# Clean any safe.directory values added to global gitconfig because of srpm and
# rpm target runs
clean-global-gitconfig:
	$(shell git config --global --unset-all safe.directory $(shell pwd)/libocispec)
	$(shell git config --global --unset-all safe.directory $(shell pwd)/rpm)
	$(shell git config --global --unset-all safe.directory /crun)

srpm:
	echo $(VERSION)
	$(MAKE) -C rpm tarball-prep
	rpmbuild -bs $(RPM_OPTS) rpm/crun.spec
	$(MAKE) clean-global-gitconfig

rpm: srpm
	rpmbuild -ba $(RPM_OPTS) rpm/crun.spec
	$(MAKE) clean-global-gitconfig

if ENABLE_LIBCRUN
lib_LTLIBRARIES = libcrun.la
else
noinst_LTLIBRARIES = libcrun.la
endif

check_LIBRARIES = libcrun_testing.a

libcrun_SOURCES = src/libcrun/utils.c \
		src/libcrun/cgroup-cgroupfs.c \
		src/libcrun/cgroup-resources.c \
		src/libcrun/cgroup-setup.c \
		src/libcrun/cgroup-systemd.c \
		src/libcrun/cgroup-utils.c \
		src/libcrun/cgroup.c \
		src/libcrun/chroot_realpath.c \
		src/libcrun/cloned_binary.c \
		src/libcrun/container.c \
		src/libcrun/criu.c \
		src/libcrun/custom-handler.c \
		src/libcrun/ebpf.c \
		src/libcrun/error.c \
		src/libcrun/handlers/handler-utils.c \
		src/libcrun/handlers/krun.c \
		src/libcrun/handlers/mono.c \
		src/libcrun/handlers/wasmedge.c \
		src/libcrun/handlers/wasmer.c \
		src/libcrun/handlers/wasmtime.c \
		src/libcrun/intelrdt.c \
		src/libcrun/io_priority.c \
		src/libcrun/linux.c \
		src/libcrun/mount_flags.c \
		src/libcrun/scheduler.c \
		src/libcrun/seccomp.c \
		src/libcrun/seccomp_notify.c \
		src/libcrun/signals.c \
		src/libcrun/status.c \
		src/libcrun/terminal.c

if HAVE_EMBEDDED_YAJL
maybe_libyajl.la = libocispec/yajl/libyajl.la
else
maybe_libyajl.la =
endif

libocispec/libocispec.la:
	$(MAKE) $(AM_MAKEFLAGS) -C libocispec libocispec.la

libcrun_la_SOURCES = $(libcrun_SOURCES)
libcrun_la_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -fvisibility=hidden
libcrun_la_LIBADD = libocispec/libocispec.la $(FOUND_LIBS) $(maybe_libyajl.la)
libcrun_la_LDFLAGS = -Wl,--version-script=$(abs_top_srcdir)/libcrun.lds

# build a version with all the symbols visible for testing
libcrun_testing_a_SOURCES = $(libcrun_SOURCES)
libcrun_testing_a_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -fvisibility=default
libcrun_testing_a_LIBADD = libocispec/libocispec.la $(maybe_libyajl.la)

if PYTHON_BINDINGS
pyexec_LTLIBRARIES = python_crun.la
python_crun_la_SOURCES = python/crun_python.c
python_crun_la_CFLAGS = -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/libocispec/src -I $(abs_top_builddir)/src $(PYTHON_CFLAGS)
python_crun_la_LDFLAGS = -avoid-version -module $(PYTHON_LDFLAGS)
python_crun_la_LIBADD = libcrun.la $(PYTHON_LIBS) $(FOUND_LIBS) $(maybe_libyajl.la)
endif

if LUA_BINDINGS
luaexec_LTLIBRARIES = luacrun.la
luacrun_la_SOURCES = lua/lua_crun.c
luacrun_la_CFLAGS = -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/libocispec/src -I $(abs_top_builddir)/src $(LUA_INCLUDE)
luacrun_la_LDFLAGS = -avoid-version -module
luacrun_la_LIBADD = libcrun.la $(LUA_LIB) $(FOUND_LIBS)

LUACRUN_CLEAN_VERSION = $(shell git describe --tags | sed 's/-g[0-9a-f]\{7,9\}//')

LUACRUN_RELEASE_VERSION = $(shell git describe --tags | sed 's/-[0-9]*-g[0-9a-f]\{7,9\}//')

LUACRUN_ROCKSPEC = luacrun-$(LUACRUN_CLEAN_VERSION).rockspec

$(LUACRUN_ROCKSPEC): lua/luacrun.rockspec
	sed -e 's/@RELEASEVERSION/$(LUACRUN_RELEASE_VERSION)/g' < lua/luacrun.rockspec | \
	sed -e 's/@CLEANVERSION/$(LUACRUN_CLEAN_VERSION)/g' > $@

LUACRUN_ROCK = luacrun-$(LUACRUN_CLEAN_VERSION).src.rock

$(LUACRUN_ROCK): dist-gzip $(LUACRUN_ROCKSPEC)
	rm -f $(LUACRUN_ROCK)
	mv "$(distdir).tar.gz" "crun-$(LUACRUN_RELEASE_VERSION).tar.gz"
	tar -xzf "crun-$(LUACRUN_RELEASE_VERSION).tar.gz" --transform="s/crun-$(VERSION)\(.*\)$$/crun-$(LUACRUN_RELEASE_VERSION)\1/"
	tar -czf "crun-$(LUACRUN_RELEASE_VERSION).tar.gz" "crun-$(LUACRUN_RELEASE_VERSION)"
	rm -rf "crun-$(LUACRUN_RELEASE_VERSION)"
	zip -j $(LUACRUN_ROCK) $(LUACRUN_ROCKSPEC) "crun-$(LUACRUN_RELEASE_VERSION).tar.gz"
	rm -f "crun-$(LUACRUN_RELEASE_VERSION).tar.gz"

dist-luarock: $(LUACRUN_ROCK)

endif

crun_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -D CRUN_LIBDIR="\"$(CRUN_LIBDIR)\""
crun_SOURCES = src/crun.c src/run.c src/delete.c src/kill.c src/pause.c src/unpause.c src/oci_features.c src/spec.c \
		src/exec.c src/list.c src/create.c src/start.c src/state.c src/update.c src/ps.c \
		src/checkpoint.c src/restore.c src/libcrun/cloned_binary.c

if DYNLOAD_LIBCRUN
crun_LDFLAGS = -Wl,--unresolved-symbols=ignore-all $(CRUN_LDFLAGS)
else
crun_LDADD = libcrun.la $(FOUND_LIBS) $(maybe_libyajl.la)
crun_LDFLAGS = $(CRUN_LDFLAGS)
endif

EXTRA_DIST = COPYING COPYING.libcrun README.md NEWS SECURITY.md rpm/crun.spec autogen.sh \
	src/crun.h src/list.h src/run.h src/delete.h src/kill.h src/pause.h src/unpause.h \
	src/create.h src/start.h src/state.h src/exec.h src/oci_features.h src/spec.h src/update.h src/ps.h \
	src/checkpoint.h src/restore.h src/libcrun/seccomp_notify.h src/libcrun/seccomp_notify_plugin.h \
	src/libcrun/container.h src/libcrun/seccomp.h src/libcrun/ebpf.h \
	src/libcrun/cgroup.h src/libcrun/cgroup-cgroupfs.h \
	src/libcrun/cgroup-internal.h \
	src/libcrun/cgroup-resources.h src/libcrun/cgroup-setup.h \
	src/libcrun/cgroup-systemd.h src/libcrun/cgroup-utils.h \
	src/libcrun/custom-handler.h src/libcrun/io_priority.h \
	src/libcrun/handlers/handler-utils.h \
	src/libcrun/linux.h src/libcrun/utils.h src/libcrun/error.h src/libcrun/criu.h \
	src/libcrun/scheduler.h src/libcrun/status.h src/libcrun/terminal.h \
	src/libcrun/mount_flags.h src/libcrun/intelrdt.h \
	crun.1.md crun.1 libcrun.lds \
	krun.1.md krun.1 \
	lua/luacrun.rockspec

UNIT_TESTS = tests/tests_libcrun_utils tests/tests_libcrun_errors tests/tests_libcrun_intelrdt

if ENABLE_CRUN
bin_PROGRAMS = crun
noinst_PROGRAMS =
else
noinst_PROGRAMS = crun
endif

noinst_PROGRAMS += tests/init $(UNIT_TESTS) tests/tests_libcrun_fuzzer

TESTS_LDADD = libcrun_testing.a $(FOUND_LIBS) $(maybe_libyajl.la)

tests_init_LDADD =
tests_init_LDFLAGS = -static-libgcc -all-static
tests_init_SOURCES = tests/init.c

tests_tests_libcrun_utils_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/src -I $(abs_top_srcdir)/src
tests_tests_libcrun_utils_SOURCES = tests/tests_libcrun_utils.c
tests_tests_libcrun_utils_LDADD = $(TESTS_LDADD)
tests_tests_libcrun_utils_LDFLAGS = $(crun_LDFLAGS)

tests_tests_libcrun_intelrdt_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/src -I $(abs_top_srcdir)/src
tests_tests_libcrun_intelrdt_SOURCES = tests/tests_libcrun_intelrdt.c
tests_tests_libcrun_intelrdt_LDADD = $(TESTS_LDADD)
tests_tests_libcrun_intelrdt_LDFLAGS = $(crun_LDFLAGS)

tests_tests_libcrun_fuzzer_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/src -I $(abs_top_srcdir)/src
tests_tests_libcrun_fuzzer_SOURCES = tests/tests_libcrun_fuzzer.c
tests_tests_libcrun_fuzzer_LDADD = $(TESTS_LDADD) libocispec/libocispec.la $(maybe_libyajl.la)
tests_tests_libcrun_fuzzer_LDFLAGS = $(crun_LDFLAGS)

tests_tests_libcrun_errors_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/src -I $(abs_top_srcdir)/src
tests_tests_libcrun_errors_SOURCES = tests/tests_libcrun_errors.c
tests_tests_libcrun_errors_LDADD = $(TESTS_LDADD)
tests_tests_libcrun_errors_LDFLAGS = $(crun_LDFLAGS)

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)
PY_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh

PYTHON_TESTS = tests/test_capabilities.py \
	tests/test_cwd.py \
	tests/test_checkpoint_restore.py \
	tests/test_devices.py \
	tests/test_hostname.py \
	tests/test_limits.py \
	tests/test_oci_features.py \
	tests/test_mounts.py \
	tests/test_paths.py \
	tests/test_pid.py \
	tests/test_pid_file.py \
	tests/test_preserve_fds.py \
	tests/test_uid_gid.py \
	tests/test_rlimits.py \
	tests/test_tty.py \
	tests/test_hooks.py \
	tests/test_update.py \
	tests/test_detach.py \
	tests/test_delete.py \
	tests/test_resources.py \
	tests/test_start.py \
	tests/test_exec.py \
	tests/test_seccomp.py \
	tests/test_time.py

TESTS = $(PYTHON_TESTS) $(UNIT_TESTS)

.version:
	$(AM_V_GEN)echo $(VERSION) > $@-t && mv $@-t $@

git-version.h:
	@if test -e $(abs_top_srcdir)/.tarball-git-version.h; then \
		cp $(abs_top_srcdir)/.tarball-git-version.h $@; \
	elif test -e $(abs_top_srcdir)/.git; then \
		version=`$(AM__GEN)git --git-dir=$(abs_top_srcdir)/.git rev-parse HEAD`; \
		$(AM__GEN)printf "/* autogenerated.  */\n#ifndef GIT_VERSION\n# define GIT_VERSION \"%s\"\n#endif\n" $$version > $@-t && mv $@-t $@; \
	fi

nixpkgs:
	@nix run -f channel:nixpkgs-unstable nix-prefetch-git -- \
		--no-deepClone https://github.com/nixos/nixpkgs > nix/nixpkgs.json

dist-hook:
	$(AM_V_GEN)echo $(VERSION) > $(distdir)/.tarball-version
	$(AM__GEN)cp git-version.h $(distdir)/.tarball-git-version.h

EXTRA_DIST += $(PYTHON_TESTS) tests/Makefile.tests tests/run_all_tests.sh tests/tests_utils.py build-aux/git-version-gen src/libcrun/signals.perf src/libcrun/mount_flags.perf
BUILT_SOURCES = .version git-version.h

CLEANFILES = crun.spec .version git-version.h $(LUACRUN_ROCKSPEC)

man1_MANS =

if ENABLE_CRUN
man1_MANS += crun.1
endif

if ENABLE_KRUN
man1_MANS += krun.1
endif

crun.1: $(abs_srcdir)/crun.1.md
if HAVE_MD2MAN
	$(MD2MAN) -in $(abs_srcdir)/crun.1.md -out crun.1
endif HAVE_MD2MAN

krun.1: $(abs_srcdir)/krun.1.md
if HAVE_MD2MAN
	$(MD2MAN) -in $(abs_srcdir)/krun.1.md -out krun.1
endif HAVE_MD2MAN

generate-man: crun.1 krun.1

sync:
	(cd libocispec; git pull https://github.com/containers/libocispec main)

coverity:
	$(MAKE) $(AM_MAKEFLAGS) -C libocispec
	$(MAKE) $(AM_MAKEFLAGS) crun

libcrun.rs: src/libcrun/container.h
	bindgen src/libcrun/container.h -- -I$(abs_builddir) -I$(abs_builddir)/libocispec/src  > $@

generate-rust-bindings: libcrun.rs

generate-signals.c: src/libcrun/signals.perf
	${GPERF} --lookup-function-name libcrun_signal_in_word_set -m 100 --null-strings --pic -tCEG -S1 $< > src/libcrun/signals.c

generate-mount_flags.c: src/libcrun/mount_flags.perf
	${GPERF} --lookup-function-name libcrun_mount_flag_in_word_set -m 100 -tCEG -S1 $< > src/libcrun/mount_flags.c

clang-format:
# do not format files that were copied into the source directory.
	git ls-files src tests | grep -E "\\.[hc]" | grep -v "chroot_realpath.c\|cloned_binary.c\|signals.c\|mount_flags.c" | xargs clang-format -style=file -i

shellcheck:
	shellcheck tests/*/*.sh contrib/*.sh

.PHONY: coverity sync generate-rust-bindings generate-signals.c generate-mount_flags.c clang-format shellcheck
