/*
 * util.c - this file is for random utilities and hypervisor backdoors
 */

#define _GNU_SOURCE
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
	tf->rax = syscall(tf->rax, tf->rdi, tf->rsi, tf->rdx, tf->rcx, tf->r8, tf->r9);
}

sighandler_t dune_signal(int sig, sighandler_t cb)
{
	dune_intr_cb x = (dune_intr_cb)cb; /* XXX */

	if (signal(sig, cb) == SIG_ERR)
		return SIG_ERR;

	dune_register_intr_handler(DUNE_SIGNAL_INTR_BASE + sig, x);

	return NULL;
}

/**
 * @brief Create an ucontext_t from a given dune_tf (i.e., from userspace state).
 * Useful for e.g. libunwind of userspace.
 */
void dune_getcontext(ucontext_t *ucp, struct dune_tf *tf)
{
#define R(x) (ucp->uc_mcontext.gregs[x])
    R(0)  = tf->r8;
    R(1)  = tf->r9;
    R(2)  = tf->r10;
    R(3)  = tf->r11;
    R(4)  = tf->r12;
    R(5)  = tf->r13;
    R(6)  = tf->r14;
    R(7)  = tf->r15;
    R(8)  = tf->rdi;
    R(9)  = tf->rsi;
    R(10) = tf->rbp;
    R(11) = tf->rbx;
    R(12) = tf->rdx;
    R(13) = tf->rax;
    R(14) = tf->rcx;
    R(15) = tf->rsp;
    R(16) = tf->rip;
#undef R
}

/**
 * @brief Set a dune_tf from a given ucontext_t (i.e., from userspace state).
 * Useful for e.g. libunwind of userspace.
 */
void dune_setcontext(const ucontext_t *ucp, struct dune_tf *tf)
{
#define R(x) (ucp->uc_mcontext.gregs[x])
    tf->r8  = R(0);
    tf->r9  = R(1);
    tf->r10 = R(2);
    tf->r11 = R(3);
    tf->r12 = R(4);
    tf->r13 = R(5);
    tf->r14 = R(6);
    tf->r15 = R(7);
    tf->rdi = R(8);
    tf->rsi = R(9);
    tf->rbp = R(10);
    tf->rbx = R(11);
    tf->rdx = R(12);
    tf->rax = R(13);
    tf->rcx = R(14);
    tf->rsp = R(15);
    tf->rip = R(16);
#undef R
}