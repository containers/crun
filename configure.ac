AC_PREREQ([2.69])
AC_INIT([crun], [0.2], [giuseppe@scrivano.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_CONFIG_SRCDIR([src/crun.c])
LT_INIT([disable-shared])

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])

AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_PROG_AWK
AC_PROG_SED
AC_PROG_CC
AM_PATH_PYTHON

AC_CHECK_HEADERS([sys/capability.h], [], [AC_MSG_ERROR([*** POSIX caps headers not found])])

AC_CHECK_HEADERS([error.h])

AC_CHECK_FUNCS(copy_file_range)

AC_CHECK_LIB(cap, cap_from_name, [AC_DEFINE([HAVE_CAP], 1, [Define if libcap is available])], [AC_MSG_ERROR([*** libcap headers not found])])
AC_CHECK_LIB(seccomp, seccomp_rule_add, [AC_DEFINE([HAVE_SECCOMP], 1, [Define if seccomp is available])], [AC_MSG_ERROR([*** libseccomp headers not found])])

AC_CHECK_LIB(seccomp, seccomp_arch_resolve_name, [AC_DEFINE([SECCOMP_ARCH_RESOLVE_NAME], 1, [Define if seccomp_arch_resolve_name is available])], [ ])

PKG_CHECK_MODULES([YAJL], [yajl >= 2.0.0])
PKG_CHECK_MODULES([SYSTEMD], [libsystemd >= 221], [AC_DEFINE([HAVE_SYSTEMD], 1, [Define if libsystemd is available])], [ ])
PKG_CHECK_MODULES([SELINUX], [libselinux >= 2.1.9], [AC_DEFINE([HAVE_SELINUX], 1, [Define if SELinux is available])], [ ])

AC_ARG_WITH([python-bindings], AS_HELP_STRING([--with-python-bindings], [build the Python bindings]))
AS_IF([test "x$with_python_bindings" = "xyes"], [
            PKG_CHECK_MODULES([PYTHON], [python], [], [AC_MSG_ERROR([*** python headers not found])])
            # configure should not touch CFLAGS/LDFLAGS but we need it to propagate it
            # to libocispec.
            CFLAGS+=" -fPIC "
            LDFLAGS+=" -fPIC "
])

AC_SEARCH_LIBS([argp_parse], [argp], [], [AC_MSG_ERROR([*** argp functions not found - install libargp or argp_standalone])])

AM_CONDITIONAL([PYTHON_BINDINGS], [test "x$with_python_bindings" = "xyes"])

AC_CONFIG_FILES([Makefile])

AC_CONFIG_SUBDIRS([libocispec])
AC_OUTPUT
