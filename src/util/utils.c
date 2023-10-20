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
#include "utils.h"

int vmpl_puts(const char *buf)
{
    int ret = hp_write(STDOUT_FILENO, buf, strlen(buf));
    return ret;
}

static char buf[1024];

int vmpl_printf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, 1024, fmt, args);
	va_end(args);

	return vmpl_puts(buf);
}