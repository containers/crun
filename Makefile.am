SUBDIRS = libocispec

noinst_LIBRARIES = libcrun.a

bin_PROGRAMS = crun

libcrun_a_SOURCES = src/libcrun/utils.c src/libcrun/container.c

libcrun_a_CFLAGS = -I $(abs_top_builddir)/libocispec/src
crun_CFLAGS = -I $(abs_top_builddir)/libocispec/src

crun_SOURCES = src/crun.c src/run.c

crun_LDADD = libcrun.a libocispec/libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

EXTRA_DIST = src/crun.h src/libcrun/container.h src/libcrun/utils.h src/run.h
