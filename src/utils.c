/*
 * util.c - this file is for random utilities and hypervisor backdoors
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include "hypercall.h"

static int vmpl_puts(const char *buf)
{
    long ret = hp_write(STDOUT_FILENO, buf, strlen(buf));
    return ret;
}

static int vmpl_printf(const char *fmt, ...)
{
	va_list args;
	char buf[1024];

	va_start(args, fmt);
	vsprintf(buf, fmt, args);
	va_end(args);

	return vmpl_puts(buf);
}