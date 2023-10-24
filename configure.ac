AC_INIT([vmpl], [1.0], [your-email@example.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Enable static linking
AC_ENABLE_STATIC

AC_PROG_CC([musl-gcc])

# Specify the desired archiver program with options
AR=ar

# Checks for programs
AM_PROG_AR
AM_PROG_AS

LT_INIT([static])

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])

AC_DEFINE([LIBVMPL_INCLUDE_DIR], [/home/benshan/vmpl-process/libvmpl/include], [libvmpl的头文件目录])
AC_DEFINE([SVSM_DEV_INCLUDE_DIR], [/home/benshan/svsm-dev], [svsm-dev的头文件目录])
AC_DEFINE([MY_CUSTOM_VAR] [1], [附加标志])

# 声明一个自定义的Automake变量
EXTRA_FLAGS="-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -msoft-float"
AC_SUBST(EXTRA_FLAGS)

AC_OUTPUT