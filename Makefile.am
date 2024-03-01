AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4
# 将config.h包含在编译中
AM_CPPFLAGS = -I$(top_srcdir)/include -I../vmpl-dev -include config.h
AM_CFLAGS = -Wall -g -O3 -MD -fPIC
AM_LDFLAGS = -L. -lvmpl -lhotcalls -ldict

# Specify shared libraries to be built
lib_LTLIBRARIES = libvmpl.la libdunify.la libdune.la
libvmpl_la_SOURCES = src/vmpl.c \
                    src/sys.c \
                    src/debug.c \
                    src/vmpl-ioctl.c \
                    src/page.c \
                    src/pgtable.c \
                    src/vma.c \
                    src/vm.c \
                    src/mm.c \
                    src/seimi.c \
                    src/ghcb.c src/vc.c \
                    src/dune.S src/vsyscall.S \
                    src/serial.c \
                    src/trap.c \
                    src/apic.c \
                    src/elf.c \
                    src/bitmap.c \
                    src/env.c \
                    src/log.c
libvmpl_la_CFLAGS = $(AM_CFLAGS)
libvmpl_la_LDFLAGS = -ldl \
                    -lhotcalls \
                    -ldict \
                    -version-info 1:0:0

libdune_la_SOURCES = src/libdune.c
libdune_la_LDFLAGS = -lvmpl

libdunify_la_SOURCES = src/dunify.c \
                    src/hotcalls.c
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
                    include/vmpl-ioctl.h \
                    include/page.h \
                    include/pgtable.h \
                    include/vma.h \
                    include/vm.h \
                    include/mm.h \
                    include/vmpl-hotcalls.h \
                    include/seimi.h \
                    include/apic.h \
                    include/elf.h \
                    include/bitmap.h \
                    include/log.h