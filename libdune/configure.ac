AC_INIT([libdune], [1.0], [your-email@example.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Enable static linking
AC_ENABLE_STATIC

# 使用 musl-gcc 作为编译器
AC_PROG_CC([musl-gcc])

# 指定 ar 程序
AR=ar

# 检查程序
AM_PROG_AR
AM_PROG_AS

# 初始化 libtool
LT_INIT([static, shared])

# 设置安装前缀
AC_PREFIX_DEFAULT([/usr/local/musl])

# 配置文件
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([libdune.c])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])

# 输出配置
AC_OUTPUT 