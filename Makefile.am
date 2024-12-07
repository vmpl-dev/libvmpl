AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4
# 将config.h包含在编译中
AM_CPPFLAGS = -I$(top_srcdir)/include -I../vmpl-dev -include config.h
AM_CFLAGS = -Wall -g -O3 -MD -fPIC -mxsave
AM_LDFLAGS = -L$(prefix)/lib

# Specify shared libraries to be built
lib_LTLIBRARIES = libvmpl.la
libvmpl_la_SOURCES = src/entry.c \
                    src/error.c \
                    src/core/_entry.S \
                    src/core/ioctl.c \
                    src/core/user.c \
                    src/core/percpu.c \
                    src/core/signals.c \
                    src/core/apic.c \
                    src/core/idt.c \
                    src/core/trap.c \
                    src/core/debug.c \
                    src/core/vmpl.c \
                    src/core/dune.c \
                    src/core/platform.c \
                    src/mm/page.c \
                    src/mm/pgtable.c \
                    src/mm/layout.c \
                    src/mm/mapping.c \
                    src/mm/procmap.c \
                    src/mm/vma.c \
                    src/mm/vm.c \
                    src/mm/mm.c \
                    src/syscall/hotcalls.c \
                    src/syscall/syscall.c \
                    src/syscall/vsyscall.S \
                    src/vc/ghcb.c \
                    src/vc/vc.c \
                    src/vc/serial.c \
                    src/security/seimi.c \
                    src/security/sys-filter.c \
                    src/utils/util.c \
                    src/utils/elf.c \
                    src/utils/env.c \
                    src/utils/log.c
libvmpl_la_CFLAGS = $(AM_CFLAGS)
libvmpl_la_LDFLAGS = -version-info 1:0:0 \
                    -L$(prefix)/lib \
                    -ldl \
                    -ldict \
                    -lhotcalls

# Add subdirectories
SUBDIRS = libdune libdunify

# Specify headers to be installed
pkgincludedir = $(includedir)/vmpl
pkginclude_HEADERS = include/vmpl.h \
                    include/error.h \
                    include/sys.h \
                    include/vc.h \
                    include/pgtable.h \
                    include/seimi.h \
                    include/elf.h \
                    include/bitmap.h \
                    include/log.h