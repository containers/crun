AC_PREREQ([2.69])
AC_INIT([crun], [0.01], [giuseppe@scrivano.org])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_SRCDIR([src/crun.c])

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])

AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_PROG_RANLIB
AC_PROG_CC

PKG_CHECK_MODULES([YAJL], [yajl >= 2.0.0])

AC_CONFIG_FILES([Makefile])

AC_CONFIG_SUBDIRS([libocispec])
AC_OUTPUT
