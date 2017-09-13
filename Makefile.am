SUBDIRS = libocispec

noinst_LIBRARIES = libcrun.a

bin_PROGRAMS = crun

libcrun_a_SOURCES = src/libcrun/utils.c \
		src/libcrun/container.c \
		src/libcrun/cgroup.c \
		src/libcrun/linux.c \
		src/libcrun/seccomp.c \
		src/libcrun/error.c \
		src/libcrun/status.c \
		src/libcrun/terminal.c

libcrun_a_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src
crun_CFLAGS = -I $(abs_top_builddir)/libocispec/src -I $(abs_top_srcdir)/libocispec/src

crun_SOURCES = src/crun.c src/run.c src/delete.c src/kill.c src/spec.c \
		src/exec.c src/list.c src/create.c src/start.c src/state.c

crun_LDADD = libcrun.a libocispec/libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

EXTRA_DIST = COPYING COPYING.libcrun README.md \
	src/crun.h src/list.h src/run.h src/delete.h src/kill.h \
	src/create.h src/start.h src/state.h src/exec.h src/spec.h \
	src/libcrun/container.h src/libcrun/seccomp.h src/libcrun/cgroup.h \
	src/libcrun/linux.h src/libcrun/utils.h src/libcrun/error.h \
	src/libcrun/status.h src/libcrun/terminal.h
