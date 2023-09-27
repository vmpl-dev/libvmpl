AC_INIT([vmpl], [1.0], [your-email@example.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Enable static linking
AC_ENABLE_STATIC

AC_PROG_CC

# Specify the desired archiver program with options
AR=ar crD

# Specify static libraries that should not be installed
noinst_LIBRARIES = libvmpl.a

# Specify shared libraries to be built
# lib_LTLIBRARIES = libvmpl.la

# Specify static libraries to be built
# lib_LIBRARIES = libvmpl.a

# Checks for programs
AM_PROG_AR
AM_PROG_AS

LT_INIT([static])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])

AC_DEFINE([LIBVMPL_INCLUDE_DIR], ["/home/benshan/vmpl-process/libvmpl/include"], [libvmpl的头文件目录])
AC_DEFINE([SVSM_DEV_INCLUDE_DIR], ["/home/benshan/svsm-dev"], [svsm-dev的头文件目录])
AC_DEFINE([EXTRA_FLAGS] [-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -msoft-float], [附加标志])

AC_OUTPUT