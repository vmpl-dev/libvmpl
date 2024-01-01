AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4
# 将config.h包含在编译中
AM_CPPFLAGS = -I$(top_srcdir)/include -I../vmpl-dev -include config.h
AM_CFLAGS = -Wall -g -O3 -MD
AM_LDFLAGS = -L. -lvmpl -lhotcalls

# Specify shared libraries to be built
lib_LTLIBRARIES = libvmpl.la libdunify.la
libvmpl_la_SOURCES = src/vmpl.c \
                    src/sys.c \
                    src/vmpl-ioctl.c \
                    src/page.c \
                    src/pgtable.c \
                    src/mm.c \
                    src/seimi.c \
                    src/hotcalls.c \
                    src/ghcb.c src/vmsa.c src/vc.c \
                    src/dune.S src/vsyscall.S \
                    src/serial.c \
                    src/trap.c \
                    src/apic.c \
                    src/bitmap.c \
                    src/env.c \
                    src/log.c
libvmpl_la_LDFLAGS = -fPIC -shared \
                    -ldl \
                    -lhotcalls \
                    -version-info 1:0:0

libdunify_la_SOURCES = src/dunify.c
libdunify_la_LDFLAGS = -fPIC -shared \
                    -ldl \
                    -lvmpl \
                    -lhotcalls \
                    -version-info 1:0:0

# Specify headers to be installed
pkgincludedir = $(includedir)/vmpl
pkginclude_HEADERS = include/vmpl.h \
                    include/dune.h \
                    include/sys.h include/syscall.h \
                    include/vc.h \
                    include/page.h \
                    include/pgtable.h \
                    include/mm.h \
                    include/hotcalls.h \
                    include/seimi.h \
                    include/apic.h \
                    include/bitmap.h \
                    include/log.h