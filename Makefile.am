AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I$(top_srcdir)/include -I../svsm-dev
AM_CFLAGS = -Wall -g -O3 -MD -static $(EXTRA_FLAGS)
AM_LDFLAGS = -L. -lvmpl

# Specify shared libraries to be built
lib_LTLIBRARIES = libvmpl.la
libvmpl_la_SOURCES = src/vmpl.c \
                    src/procmap.c \
                    src/sys.c \
                    src/mm.c \
                    src/ghcb.c src/vmsa.c src/vc.c \
                    src/dune.S src/vsyscall.S \
                    src/serial.c \
                    src/hypercall.c
libvmpl_la_CFLAGS = -Wall -g -O3 -MD -static -DVERBOSE
libvmpl_la_LDFLAGS = -static -L.
# 将config.h包含在编译中
my_program_CPPFLAGS = -include config.h

# 指定需要安装的头文件
# include_HEADERS =