DIST_SUBDIRS = libocispec
SUBDIRS = libocispec
ACLOCAL_AMFLAGS = -I m4

WD := $(shell pwd)

crun.spec: $(srcdir)/rpm/crun.spec.template
	sed -e 's|#VERSION#|$(VERSION)|g' < $< > $@

rpm: dist-gzip crun.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-xz
	rpmbuild -ba --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" crun.spec

srpm: dist-gzip crun.spec
	echo $(VERSION)
	$(MAKE) -C $(WD) dist-xz
	rpmbuild -bs --define "_sourcedir $(WD)" --define "_specdir $(WD)" --define "_builddir $(WD)" --define "_srcrpmdir $(WD)" --define "_rpmdir $(WD)" --define "_buildrootdir $(WD)/.build" crun.spec

oci-runtime-validation:
	RUNTIME=$(CURDIR)/crun tests/oci-runtime-validation

CLEANFILES = crun.spec

lib_LTLIBRARIES = libcrun.la

libcrun_la_SOURCES = src/libcrun/utils.c \
			src/libcrun/cloned_binary.c \
			src/libcrun/container.c \
			src/libcrun/cgroup.c \
			src/libcrun/linux.c \
			src/libcrun/seccomp.c \
			src/libcrun/error.c \
			src/libcrun/status.c \
			src/libcrun/terminal.c \
			src/libcrun/sig2str.c

libcrun_la_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src
libcrun_la_LIBADD = libocispec/libocispec.la

COMMON_LIBS = $(SELINUX_LIBS) $(YAJL_LIBS) -lcap -lseccomp $(SYSTEMD_LIBS)

if PYTHON_BINDINGS
pyexec_LTLIBRARIES = python_crun.la
python_crun_la_SOURCES = python/crun_python.c
python_crun_la_CFLAGS = -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/libocispec/src -I $(abs_top_builddir)/src $(PYTHON_CFLAGS)
python_crun_la_LDFLAGS = -avoid-version -module $(PYTHON_LDFLAGS)
python_crun_la_LIBADD = libcrun.la $(COMMON_LIBS) $(PYTHON_LIBS)
endif

crun_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src
crun_SOURCES = src/crun.c src/run.c src/delete.c src/kill.c src/pause.c src/unpause.c src/spec.c \
		src/exec.c src/list.c src/create.c src/start.c src/state.c src/update.c
crun_LDADD = libcrun.la $(COMMON_LIBS)

EXTRA_DIST = COPYING COPYING.libcrun README.md rpm/crun.spec.template autogen.sh \
	src/crun.h src/list.h src/run.h src/delete.h src/kill.h src/pause.h src/unpause.h \
	src/create.h src/start.h src/state.h src/exec.h src/spec.h src/update.h \
	src/libcrun/container.h src/libcrun/seccomp.h src/libcrun/cgroup.h \
	src/libcrun/linux.h src/libcrun/utils.h src/libcrun/error.h \
	src/libcrun/status.h src/libcrun/terminal.h src/libcrun/sig2str.h \
	src/libcrun/intprops.h

UNIT_TESTS = tests/tests_libcrun_utils tests/tests_libcrun_errors

bin_PROGRAMS = crun
noinst_PROGRAMS = tests/init $(UNIT_TESTS)

tests_init_LDFLAGS = -static-libgcc -all-static
tests_init_SOURCES = tests/init.c $(UNIT_TESTS)

tests_tests_libcrun_utils_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/src
tests_tests_libcrun_utils_SOURCES = tests/tests_libcrun_utils.c
tests_tests_libcrun_utils_LDADD = $(crun_LDADD)
tests_tests_libcrun_utils_LDFLAGS = $(crun_LDFLAGS)

tests_tests_libcrun_errors_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src -I $(abs_top_builddir)/src
tests_tests_libcrun_errors_SOURCES = tests/tests_libcrun_errors.c
tests_tests_libcrun_errors_LDADD = $(crun_LDADD)
tests_tests_libcrun_errors_LDFLAGS = $(crun_LDFLAGS)

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)
PY_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh

TESTS = tests/test_capabilities.py \
	tests/test_cwd.py \
	tests/test_devices.py \
	tests/test_hostname.py \
	tests/test_limits.py \
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
	tests/test_resources.py \
	tests/test_start.py \
	tests/test_exec.py \
	$(UNIT_TESTS)

EXTRA_DIST += $(TESTS) tests/tests_utils.py

sync:
	(cd libocispec; git pull https://github.com/giuseppe/libocispec)
