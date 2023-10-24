AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4
# 将config.h包含在编译中
AM_CPPFLAGS = -I$(top_srcdir)/include -I../svsm-dev -include config.h
AM_CFLAGS = -Wall -g -O3 -MD -static
AM_LDFLAGS = -static -L. -lvmpl

# Specify shared libraries to be built
lib_LTLIBRARIES = libvmpl.la
libvmpl_la_SOURCES = src/vmpl.c \
                    src/sys.c \
                    src/mm.c \
                    src/ghcb.c src/vmsa.c src/vc.c \
                    src/dune.S src/vsyscall.S \
                    src/trap.c

# Specify headers to be installed
pkgincludedir = $(includedir)/vmpl
pkginclude_HEADERS = include/vmpl.h include/sys.h include/cpu-x86.h