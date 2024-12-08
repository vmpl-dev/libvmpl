AC_INIT([vmpl], [1.0], [your-email@example.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Enable static linking
AC_ENABLE_STATIC

AC_PROG_CC([musl-gcc])
AC_PROG_INSTALL

# Specify the desired archiver program with options
AR=ar

# Checks for programs
AM_PROG_AR
AM_PROG_AS

LT_INIT([static, shared])

# Add subdirectories
AC_CONFIG_SUBDIRS([libdune libdunify])

# Set installation prefix
AC_PREFIX_DEFAULT([/usr/local/musl])
AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])

AC_ARG_WITH([vmpl-va-start], [AS_HELP_STRING([--with-vmpl-va-start],
                                              [Set vmpl va start])],
            [with_vmpl_va_start=$withval],
            [with_vmpl_va_start=0x3fffff000000UL])
AC_DEFINE_UNQUOTED([CONFIG_VMPL_VA_START], [$with_vmpl_va_start], [vmpl va start])

AC_ARG_WITH([vmpl-va-size], [AS_HELP_STRING([--with-vmpl-va-size],
                                             [Set vmpl va size])],
            [with_vmpl_va_size=$withval],
            [with_vmpl_va_size=0x20000000UL])
AC_DEFINE_UNQUOTED([CONFIG_VMPL_VA_SIZE], [$with_vmpl_va_size], [vmpl va size])

AC_ARG_WITH([vmpl-fit-algorithm], [AS_HELP_STRING([--with-vmpl-fit-algorithm],
                                                  [Set vmpl fit algorithm])],
            [with_vmpl_fit_algorithm=$withval],
            [with_vmpl_fit_algorithm=2])
AC_DEFINE_UNQUOTED([CONFIG_VMPL_FIT_ALGORITHM], [$with_vmpl_fit_algorithm], [vmpl fit algorithm])

AC_ARG_WITH([vmpl-page-grow-size], [AS_HELP_STRING([--with-vmpl-page-grow-size],
                                                   [Set vmpl page grow size])],
            [with_vmpl_page_grow_size=$withval],
            [with_vmpl_page_grow_size=0x400])
AC_DEFINE_UNQUOTED([CONFIG_VMPL_PAGE_GROW_SIZE], [$with_vmpl_page_grow_size], [vmpl page grow size])

AC_ARG_WITH([dune-page-grow-size], [AS_HELP_STRING([--with-dune-page-grow-size],
                                                   [Set dune page grow size])],
            [with_dune_page_grow_size=$withval],
            [with_dune_page_grow_size=0x200])
AC_DEFINE_UNQUOTED([CONFIG_DUNE_PAGE_GROW_SIZE], [$with_dune_page_grow_size], [dune page grow size])

AC_ARG_ENABLE([vmpl-banner],
              [AS_HELP_STRING([--enable-vmpl-banner],
                              [Enable vmpl banner support])],
              [enable_vmpl_banner=$enableval],
              [enable_vmpl_banner=no])
AM_CONDITIONAL([ENABLE_VMPL_BANNER], [test "x$enable_vmpl_banner" = "xyes"])

AC_ARG_ENABLE([vmpl-stats],
              [AS_HELP_STRING([--enable-vmpl-stats],
                              [Enable vmpl stats support])],
              [enable_vmpl_stats=$enableval],
              [enable_vmpl_stats=no])
AM_CONDITIONAL([ENABLE_VMPL_STATS], [test "x$enable_vmpl_stats" = "xyes"])

AC_ARG_ENABLE([vmpl-test], [AS_HELP_STRING([--enable-vmpl-test],
                                           [Enable vmpl test support])],
              [enable_vmpl_test=$enableval],
              [enable_vmpl_test=no])
AM_CONDITIONAL([ENABLE_VMPL_TEST], [test "x$enable_vmpl_test" = "xyes"])

AC_ARG_ENABLE([vmpl-cpuset],
              [AS_HELP_STRING([--enable-vmpl-cpuset],
                              [Enable cpuset support])],
              [enable_vmpl_cpuset=$enableval],
              [enable_vmpl_cpuset=no])
AM_CONDITIONAL([ENABLE_VMPL_CPUSET], [test "x$enable_vmpl_cpuset" = "xyes"])

AC_ARG_ENABLE([vmpl-signal],
              [AS_HELP_STRING([--enable-vmpl-signal],
                              [Enable signal support])],
              [enable_vmpl_signal=$enableval],
              [enable_vmpl_signal=no])
AM_CONDITIONAL([ENABLE_VMPL_SIGNAL], [test "x$enable_vmpl_signal" = "xyes"])

AC_ARG_ENABLE([vmpl-apic],
              [AS_HELP_STRING([--enable-vmpl-apic],
                              [Enable apic support])],
              [enable_vmpl_apic=$enableval],
              [enable_vmpl_apic=yes])
AM_CONDITIONAL([ENABLE_VMPL_APIC], [test "x$enable_vmpl_apic" = "xyes"])

AC_ARG_ENABLE([vmpl-msr-protocol], [AS_HELP_STRING([--enable-vmpl-msr-protocol],
                                                    [Enable msr protocol support])],
              [enable_vmpl_msr_protocol=$enableval],
              [enable_vmpl_msr_protocol=no])
AM_CONDITIONAL([ENABLE_VMPL_MSR_PROTOCOL], [test "x$enable_vmpl_msr_protocol" = "xyes"])

AC_ARG_ENABLE([vmpl-ghcb],
              [AS_HELP_STRING([--enable-vmpl-ghcb],
                              [Enable ghcb support])],
              [enable_vmpl_ghcb=$enableval],
              [enable_vmpl_ghcb=no])
AM_CONDITIONAL([ENABLE_VMPL_GHCB], [test "x$enable_vmpl_ghcb" = "xyes"])

AC_ARG_ENABLE([vmpl-mm], [AS_HELP_STRING([--enable-vmpl-mm],
                                         [Enable mm support])],
              [enable_vmpl_mm=$enableval],
              [enable_vmpl_mm=no])
AM_CONDITIONAL([ENABLE_VMPL_MM], [test "x$enable_vmpl_mm" = "xyes"])

AC_ARG_ENABLE([vmpl-seimi],
              [AS_HELP_STRING([--enable-vmpl-seimi],
                              [Enable seimi support])],
              [enable_vmpl_seimi=$enableval],
              [enable_vmpl_seimi=no])
AM_CONDITIONAL([ENABLE_VMPL_SEIMI], [test "x$enable_vmpl_seimi" = "xyes"])

AC_ARG_ENABLE([vmpl-debug],
              [AS_HELP_STRING([--enable-vmpl-debug],
                              [Enable debug support])],
              [enable_vmpl_debug=$enableval],
              [enable_vmpl_debug=no])
AM_CONDITIONAL([ENABLE_VMPL_DEBUG], [test "x$enable_vmpl_debug" = "xyes"])

AC_ARG_ENABLE([vmpl-hotcalls], [AS_HELP_STRING([--enable-vmpl-hotcalls],
                                               [Enable hotcalls support])],
              [enable_vmpl_hotcalls=$enableval],
              [enable_vmpl_hotcalls=no])
AM_CONDITIONAL([ENABLE_VMPL_HOTCALLS], [test "x$enable_vmpl_hotcalls" = "xyes"])

AC_ARG_ENABLE([sys-filter], [AS_HELP_STRING([--enable-sys-filter],
                                            [Enable sys filter support])],
              [enable_sys_filter=$enableval],
              [enable_sys_filter=no])
AM_CONDITIONAL([ENABLE_SYS_FILTER], [test "x$enable_sys_filter" = "xyes"])

AC_ARG_ENABLE([dump-details],
              [AS_HELP_STRING([--enable-dump-details],
                              [Enable dump details support])],
              [enable_dump_details=$enableval],
              [enable_dump_details=no])
AM_CONDITIONAL([ENABLE_DUMP_DETAILS], [test "x$enable_dump_details" = "xyes"])

AC_ARG_ENABLE([pgtable-la57],
              [AS_HELP_STRING([--enable-pgtable-la57],
                              [Enable pgtable la57 support])],
              [enable_pgtable_la57=$enableval],
              [enable_pgtable_la57=no])
AM_CONDITIONAL([ENABLE_PGTABLE_LA57], [test "x$enable_pgtable_la57" = "xyes"])

AC_ARG_ENABLE([stack-trace],
              [AS_HELP_STRING([--enable-stack-trace],
                              [Enable stack trace support])],
              [enable_stack_trace=$enableval],
              [enable_stack_trace=no])
AM_CONDITIONAL([ENABLE_STACK_TRACE], [test "x$enable_stack_trace" = "xyes"])

AC_ARG_WITH([stack-depth], [AS_HELP_STRING([--with-stack-depth],
                                           [Set stack depth])],
            [with_stack_depth=$withval],
            [with_stack_depth=12])
AC_DEFINE_UNQUOTED([CONFIG_STACK_DEPTH], [$with_stack_depth], [stack depth])

AC_ARG_ENABLE([serial-port],
              [AS_HELP_STRING([--enable-serial-port],
                              [Enable serial port support])],
              [enable_serial_port=$enableval],
              [enable_serial_port=no])
AM_CONDITIONAL([ENABLE_SERIAL_PORT], [test "x$enable_serial_port" = "xyes"])

AS_IF([test "x$enable_vmpl_syscall" = "xyes" -a "$x$enable_vmpl_seimi" = "xyes"],
      [AC_MSG_ERROR([syscall and seimi can not be enabled at the same time])])

AC_DEFINE([LIBVMPL_INCLUDE_DIR], [/home/benshan/vmpl-process/libvmpl/include], [libvmpl的头文件目录])
AC_DEFINE([SVSM_DEV_INCLUDE_DIR], [/home/benshan/svsm-dev], [svsm-dev的头文件目录])
AC_DEFINE([MY_CUSTOM_VAR] [1], [附加标志])

if test "x$enable_vmpl_banner" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_BANNER], [1], [Enable vmpl banner support])
fi

if test "x$enable_vmpl_stats" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_STATS], [1], [Enable vmpl stats support])
fi

if test "x$enable_vmpl_test" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_TEST], [1], [Enable vmpl test support])
fi

if test "x$enable_vmpl_cpuset" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_CPUSET], [1], [Enable cpuset support])
fi

if test "x$enable_vmpl_apic" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_APIC], [1], [Enable apic support])
fi

if test "x$enable_vmpl_signal" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_SIGNAL], [1], [Enable signal support])
fi

if test "x$enable_vmpl_msr_protocol" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_MSR_PROTOCOL], [1], [Enable msr protocol support])
fi

if test "x$enable_vmpl_ghcb" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_GHCB], [1], [Enable ghcb support])
fi

if test "x$enable_vmpl_mm" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_MM], [1], [Enable mm support])
fi

if test "x$enable_vmpl_seimi" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_SEIMI], [1], [Enable seimi support])
fi

if test "x$enable_vmpl_debug" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_DEBUG], [1], [Enable debug support])
fi

if test "x$enable_vmpl_hotcalls" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_HOTCALLS], [1], [Enable hotcalls support])
fi

if test "x$enable_sys_filter" = "xyes"; then
    AC_DEFINE([CONFIG_SYS_FILTER], [1], [Enable sys filter support])
fi

if test "x$enable_dump_details" = "xyes"; then
    AC_DEFINE([CONFIG_DUMP_DETAILS], [1], [Enable dump details support])
fi

if test "x$enable_pgtable_la57" = "xyes"; then
    AC_DEFINE([CONFIG_PGTABLE_LA57], [1], [Enable pgtable la57 support])
fi

if test "x$enable_stack_trace" = "xyes"; then
    AC_DEFINE([CONFIG_STACK_TRACE], [1], [Enable stack trace support])
fi

if test "x$enable_vmpl_ghcb" = "xyes" -a "x$enable_serial_port" = "xyes"; then
    AC_DEFINE([CONFIG_SERIAL_PORT], [1], [Enable serial port support])
fi

# 声明一个自定义的Automake变量
EXTRA_FLAGS="-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -msoft-float"
AC_SUBST(EXTRA_FLAGS)

AC_OUTPUT