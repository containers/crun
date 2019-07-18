AC_PREREQ([2.69])
AC_INIT([crun], [0.7], [giuseppe@scrivano.org])
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

AC_CHECK_FUNCS(copy_file_range bpf)

AC_SEARCH_LIBS(cap_from_name, [cap], [AC_DEFINE([HAVE_CAP], 1, [Define if libcap is available])], [AC_MSG_ERROR([*** libcap headers not found])])
AC_SEARCH_LIBS(seccomp_rule_add, [seccomp], [AC_DEFINE([HAVE_SECCOMP], 1, [Define if seccomp is available])], [AC_MSG_ERROR([*** libseccomp headers not found])])
AC_SEARCH_LIBS(seccomp_arch_resolve_name, [seccomp], [AC_DEFINE([SECCOMP_ARCH_RESOLVE_NAME], 1, [Define if seccomp_arch_resolve_name is available])], [ ])
AC_SEARCH_LIBS(sd_listen_fds, [systemd], [AC_DEFINE([HAVE_SYSTEMD], 1, [Define if libsystemd is available])], [ ])
AC_SEARCH_LIBS(setfilecon, [selinux], [AC_DEFINE([HAVE_SELINUX], 1, [Define if SELinux is available])], [ ])
AC_SEARCH_LIBS(yajl_tree_get, [yajl], [AC_DEFINE([HAVE_YAJL], 1, [Define if libyajl is available])], [AC_MSG_ERROR([*** libyajl headers not found])])



AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <linux/bpf.h>
int program = BPF_PROG_TYPE_CGROUP_DEVICE;
]])], [AC_DEFINE([HAVE_EBPF], 1, [Define if eBPF is available])], [])

PKG_CHECK_MODULES([YAJL], [yajl >= 2.0.0])

AC_ARG_WITH([python-bindings], AS_HELP_STRING([--with-python-bindings], [build the Python bindings]))
AS_IF([test "x$with_python_bindings" = "xyes"], [
            PKG_CHECK_MODULES([PYTHON], [python], [], [AC_MSG_ERROR([*** python headers not found])])
            # configure should not touch CFLAGS/LDFLAGS but we need it to propagate it
            # to libocispec.
            CFLAGS+=" -fPIC "
            LDFLAGS+=" -fPIC "
])

FOUND_LIBS=$LIBS
LIBS=""

AC_SUBST([FOUND_LIBS])
AC_SUBST([CRUN_LDFLAGS])

AC_SEARCH_LIBS([argp_parse], [argp], [], [AC_MSG_ERROR([*** argp functions not found - install libargp or argp_standalone])])

AM_CONDITIONAL([PYTHON_BINDINGS], [test "x$with_python_bindings" = "xyes"])

AC_CONFIG_FILES([Makefile])

AC_CONFIG_SUBDIRS([libocispec])
AC_OUTPUT
