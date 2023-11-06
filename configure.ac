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

LT_INIT([static, shared])

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])

AC_ARG_ENABLE([vmpl-cpuset],
              [AS_HELP_STRING([--enable-vmpl-cpuset],
                              [Enable cpuset support])],
              [enable_vmpl_cpuset=$enableval],
              [enable_vmpl_cpuset=no])
AM_CONDITIONAL([ENABLE_VMPL_CPUSET], [test "x$enable_vmpl_cpuset" = "xyes"])

AC_ARG_ENABLE([vmpl-apic],
              [AS_HELP_STRING([--enable-vmpl-apic],
                              [Enable apic support])],
              [enable_vmpl_apic=$enableval],
              [enable_vmpl_apic=no])
AM_CONDITIONAL([ENABLE_VMPL_APIC], [test "x$enable_vmpl_apic" = "xyes"])

AC_ARG_ENABLE([vmpl-ghcb],
              [AS_HELP_STRING([--enable-vmpl-ghcb],
                              [Enable ghcb support])],
              [enable_vmpl_ghcb=$enableval],
              [enable_vmpl_ghcb=no])
AM_CONDITIONAL([ENABLE_VMPL_GHCB], [test "x$enable_vmpl_ghcb" = "xyes"])

AC_ARG_ENABLE([vmpl-pgtable],
              [AS_HELP_STRING([--enable-vmpl-pgtable],
                              [Enable pgtable support])],
              [enable_vmpl_pgtable=$enableval],
              [enable_vmpl_pgtable=no])
AM_CONDITIONAL([ENABLE_VMPL_PGTABLE], [test "x$enable_vmpl_pgtable" = "xyes"])

AC_ARG_ENABLE([vmpl-seimi],
              [AS_HELP_STRING([--enable-vmpl-seimi],
                              [Enable seimi support])],
              [enable_vmpl_seimi=$enableval],
              [enable_vmpl_seimi=no])
AM_CONDITIONAL([ENABLE_VMPL_SEIMI], [test "x$enable_vmpl_seimi" = "xyes"])

AC_ARG_ENABLE([vmpl-syscall],
              [AS_HELP_STRING([--enable-vmpl-syscall],
                              [Enable syscall support])],
              [enable_vmpl_syscall=$enableval],
              [enable_vmpl_syscall=no])
AM_CONDITIONAL([ENABLE_VMPL_SYSCALL], [test "x$enable_vmpl_syscall" = "xyes"])

AC_ARG_ENABLE([vmpl-vsyscall],
                [AS_HELP_STRING([--enable-vmpl-vsyscall],
                                [Enable vsyscall support])],
                [enable_vmpl_vsyscall=$enableval],
                [enable_vmpl_vsyscall=no])
AM_CONDITIONAL([ENABLE_VMPL_VSYSCALL], [test "x$enable_vmpl_vsyscall" = "xyes"])

AC_ARG_ENABLE([vmpl-debug],
              [AS_HELP_STRING([--enable-vmpl-debug],
                              [Enable debug support])],
              [enable_vmpl_debug=$enableval],
              [enable_vmpl_debug=no])
AM_CONDITIONAL([ENABLE_VMPL_DEBUG], [test "x$enable_vmpl_debug" = "xyes"])

AC_ARG_ENABLE([dune-boot],
              [AS_HELP_STRING([--enable-dune-boot],
                              [Enable dune boot support])],
              [enable_dune_boot=$enableval],
              [enable_dune_boot=no])
AM_CONDITIONAL([ENABLE_DUNE_BOOT], [test "x$enable_dune_boot" = "xyes"])

AC_ARG_ENABLE([remap-syscall],
              [AS_HELP_STRING([--enable-remap-syscall],
                              [Enable remap syscall support])],
              [enable_remap_syscall=$enableval],
              [enable_remap_syscall=no])
AM_CONDITIONAL([ENABLE_REMAP_SYSCALL], [test "x$enable_remap_syscall" = "xyes"])

AC_ARG_ENABLE([remap-vsyscall],
              [AS_HELP_STRING([--enable-remap-vsyscall],
                              [Enable remap vsyscall support])],
              [enable_remap_vsyscall=$enableval],
              [enable_remap_vsyscall=no])
AM_CONDITIONAL([ENABLE_REMAP_VSYSCALL], [test "x$enable_remap_vsyscall" = "xyes"])

AC_ARG_ENABLE([dump-details],
              [AS_HELP_STRING([--enable-dump-details],
                              [Enable dump details support])],
              [enable_dump_details=$enableval],
              [enable_dump_details=no])
AM_CONDITIONAL([ENABLE_DUMP_DETAILS], [test "x$enable_dump_details" = "xyes"])

AC_ARG_ENABLE([pgtbale-la57],
              [AS_HELP_STRING([--enable-pgtbale-la57],
                              [Enable pgtbale la57 support])],
              [enable_pgtbale_la57=$enableval],
              [enable_pgtbale_la57=no])
AM_CONDITIONAL([ENABLE_PGTBALE_LA57], [test "x$enable_pgtbale_la57" = "xyes"])

AC_ARG_ENABLE([pgtable-selftest],
              [AS_HELP_STRING([--enable-pgtable-selftest],
                              [Enable pgtable selftest support])],
              [enable_pgtable_selftest=$enableval],
              [enable_pgtable_selftest=no])
AM_CONDITIONAL([ENABLE_PGTBALE_SELFTEST], [test "x$enable_pgtable_selftest" = "xyes"])

AC_ARG_ENABLE([stack-trace],
              [AS_HELP_STRING([--enable-stack-trace],
                              [Enable stack trace support])],
              [enable_stack_trace=$enableval],
              [enable_stack_trace=no])
AM_CONDITIONAL([ENABLE_STACK_TRACE], [test "x$enable_stack_trace" = "xyes"])

AC_ARG_ENABLE([ghcb-selftest],
              [AS_HELP_STRING([--enable-ghcb-selftest],
                              [Enable ghcb selftest support])],
              [enable_ghcb_selftest=$enableval],
              [enable_ghcb_selftest=no])
AM_CONDITIONAL([ENABLE_GHCB_SELFTEST], [test "x$enable_ghcb_selftest" = "xyes"])

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

if test "x$enable_vmpl_cpuset" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_CPUSET], [1], [Enable cpuset support])
fi

if test "x$enable_vmpl_apic" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_APIC], [1], [Enable apic support])
fi

if test "x$enable_vmpl_ghcb" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_GHCB], [1], [Enable ghcb support])
fi

if test "x$enable_vmpl_pgtable" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_PGTABLE], [1], [Enable pgtable support])
fi

if test "x$enable_vmpl_seimi" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_SEIMI], [1], [Enable seimi support])
fi

if test "x$enable_vmpl_syscall" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_SYSCALL], [1], [Enable syscall support])
fi

if test "x$enable_vmpl_vsyscall" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_VSYSCALL], [1], [Enable vsyscall support])
fi

if test "x$enable_vmpl_debug" = "xyes"; then
    AC_DEFINE([CONFIG_VMPL_DEBUG], [1], [Enable debug support])
fi

if test "x$enable_dune_boot" = "xyes"; then
    AC_DEFINE([CONFIG_DUNE_BOOT], [1], [Enable dune boot support])
fi

if test "x$enable_remap_syscall" = "xyes"; then
    AC_DEFINE([CONFIG_REMAP_SYSCALL], [1], [Enable remap syscall support])
fi

if test "x$enable_remap_vsyscall" = "xyes"; then
    AC_DEFINE([CONFIG_REMAP_VSYSCALL], [1], [Enable remap vsyscall support])
fi

if test "x$enable_dump_details" = "xyes"; then
    AC_DEFINE([CONFIG_DUMP_DETAILS], [1], [Enable dump details support])
fi

if test "x$enable_pgtbale_la57" = "xyes"; then
    AC_DEFINE([CONFIG_PGTBALE_LA57], [1], [Enable pgtbale la57 support])
fi

if test "x$enable_pgtable_selftest" = "xyes"; then
    AC_DEFINE([CONFIG_PGTBALE_SELFTEST], [1], [Enable pgtable selftest support])
fi

if test "x$enable_stack_trace" = "xyes"; then
    AC_DEFINE([CONFIG_STACK_TRACE], [1], [Enable stack trace support])
fi

if test "x$enable_ghcb_selftest" = "xyes"; then
    AC_DEFINE([CONFIG_GHCB_SELFTEST], [1], [Enable ghcb selftest support])
fi

if test "x$enable_vmpl_ghcb" = "xyes" -a "x$enable_serial_port" = "xyes"; then
    AC_DEFINE([CONFIG_SERIAL_PORT], [1], [Enable serial port support])
fi

# 声明一个自定义的Automake变量
EXTRA_FLAGS="-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -msoft-float"
AC_SUBST(EXTRA_FLAGS)

AC_OUTPUT