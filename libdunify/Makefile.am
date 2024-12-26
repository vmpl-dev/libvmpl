ACLOCAL_AMFLAGS = -I m4

# 继承顶层的编译选项并添加本地路径
AM_CPPFLAGS = -I$(top_srcdir)/include \
              -I$(top_builddir)/include \
              -I$(top_srcdir)/../vmpl-dev \
              -I../include \
              -include config.h

AM_CFLAGS = -Wall -g -O3 -MD -fPIC -mxsave
AM_LDFLAGS = -L.

# Specify shared libraries to be built
lib_LTLIBRARIES = libdunify.la

libdunify_la_SOURCES = dunify.c
libdunify_la_CFLAGS = $(AM_CFLAGS)
libdunify_la_LDFLAGS = -fPIC -shared \
                    -Wl,--no-undefined \
                    -version-info 1:0:0

# 添加依赖库
libdunify_la_LIBADD = -ldl -lvmpl -ldict -lhotcalls