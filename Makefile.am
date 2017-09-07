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

libcrun_a_CFLAGS = -I $(abs_top_builddir)/libocispec/src
crun_CFLAGS = -I $(abs_top_builddir)/libocispec/src

crun_SOURCES = src/crun.c src/run.c src/delete.c src/kill.c

crun_LDADD = libcrun.a libocispec/libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

EXTRA_DIST = src/crun.h src/run.h src/seccomp.h src/delete.h src/kill.h \
	src/libcrun/container.h src/libcrun/cgroup.h src/libcrun/linux.h \
	src/libcrun/utils.h src/libcrun/error.h src/libcrun/status.h
	src/libcrun/terminal.h
