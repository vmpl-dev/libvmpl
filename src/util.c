/*
 * util.c - this file is for random utilities and hypervisor backdoors
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "vmpl.h"

static int dune_puts(const char *buf)
{
	return syscall(SYS_write, STDOUT_FILENO, buf, strlen(buf));
}

/**
 * dune_printf - a raw low-level printf request that uses a hypercall directly
 * 
 * This is intended for working around libc syscall issues.
 */
int dune_printf(const char *fmt, ...)
{
	va_list args;
	char buf[1024];

	va_start(args, fmt);

	vsprintf(buf, fmt, args);

	return dune_puts(buf);
}

void *dune_mmap(void *addr, size_t length, int prot, int flags, int fd,
				off_t offset)
{
	return syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
}

/**
 * dune_die - kills the Dune process immediately
 *
 */
void dune_die(void)
{
	syscall(SYS_exit);
}

/**
 * dune_passthrough_syscall - makes a syscall using the args of a trap frame
 *
 * @tf: the trap frame to apply
 * 
 * sets the return code in tf->rax
 */
void dune_passthrough_syscall(struct dune_tf *tf)
{
	tf->rax = syscall(tf->rax, tf->rdi, tf->rsi, tf->rdx, tf->r10, tf->r8, tf->r9);
}

sighandler_t dune_signal(int sig, sighandler_t cb)
{
	dune_intr_cb x = (dune_intr_cb)cb; /* XXX */

	if (signal(sig, cb) == SIG_ERR)
		return SIG_ERR;

	dune_register_intr_handler(DUNE_SIGNAL_INTR_BASE + sig, x);

	return NULL;
}