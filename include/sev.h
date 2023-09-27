#ifndef __SEV_H_
#define __SEV_H_

#include <asm/msr.h>

/*
 * arch/x86/boot/msr.h
 * The kernel proper already defines rdmsr()/wrmsr(), but they are not for the
 * boot kernel since they rely on tracepoint/exception handling infrastructure
 * that's not available here.
 */
static inline void boot_rdmsr(unsigned int reg, struct msr *m)
{
	asm volatile("rdmsr" : "=a" (m->l), "=d" (m->h) : "c" (reg));
}

static inline void boot_wrmsr(unsigned int reg, const struct msr *m)
{
	asm volatile("wrmsr" : : "c" (reg), "a"(m->l), "d" (m->h) : "memory");
}

#endif