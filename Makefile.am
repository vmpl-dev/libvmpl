AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

# Specify static libraries that should not be installed
noinst_LIBRARIES = libvmpl.a
libvmpl_a_SOURCES = src/vmpl.c src/procmap.c src/ghcb.c src/vmsa.c src/dune.S src/vsyscall.S src/vc.c src/serial.c
libvmpl_a_CFLAGS = -static $(EXTRA_FLAGS)

# Specify shared libraries to be built
# lib_LTLIBRARIES = libvmpl.la
# libvmpl_la_CFLAGS = -shared
# libvmpl_la_SOURCES = src/vmpl.c src/procmap.c src/ghcb.c src/vmsa.c src/dune.S src/vsyscall.S

# Specify static libraries to be built
# lib_LIBRARIES = libvmpl.a
# libvmpl_a_CFLAGS = -static
# libvmpl_a_SOURCES = src/vmpl.c src/procmap.c src/ghcb.c src/vmsa.c src/dune.S src/vsyscall.S

# 指定需要安装的头文件
# include_HEADERS =

# 指定包含路径

AM_CPPFLAGS = -I$(top_srcdir)/include -I/home/benshan/svsm-dev
AM_CFLAGS = -Wall -g -O3 -MD $(EXTRA_FLAGS)
AM_LDFLAGS = -static -L. -lvmpl