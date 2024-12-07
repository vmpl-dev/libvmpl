ACLOCAL_AMFLAGS = -I m4

# 编译选项
AM_CPPFLAGS = -I$(top_srcdir)/include \
              -I$(top_builddir)/include \
              -I$(top_srcdir)/../vmpl-dev \
              -I../include \
              -include config.h

AM_CFLAGS = -Wall -g -O3 -MD -fPIC -mxsave
AM_LDFLAGS = -L$(prefix)/lib

# 库定义
lib_LTLIBRARIES = libdune.la

# 源文件和链接选项
libdune_la_SOURCES = libdune.c
libdune_la_CFLAGS = $(AM_CFLAGS)
libdune_la_LDFLAGS = -version-info 1:0:0 \
                     -L$(prefix)/lib \
                     -Wl,--no-undefined \
                     -lvmpl \
                     -ldict \
                     -lhotcalls

# 添加依赖库
libdune_la_LIBADD = -lvmpl -ldict -lhotcalls

# 头文件安装
pkgincludedir = $(includedir)/dune
pkginclude_HEADERS = dune.h

# 确保所有目标都能被构建
all-local: $(lib_LTLIBRARIES)

# 清理规则
clean-local:
	rm -f *.o *.lo *.la
	rm -rf .libs