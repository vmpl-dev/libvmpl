#ifndef __VMPL_H_
#define __VMPL_H_

#include <stdint.h>
#include <stdbool.h>

#include "svsm-vmpl.h"

#define MAX_LINE_LENGTH 256

// assembly routines from dune.S
extern int __dune_enter(int fd, struct dune_config *config);
extern int __dune_ret(void);
extern void __dune_syscall(void);
extern void __dune_syscall_end(void);
extern void __dune_intr(void);
extern void __dune_go_linux(struct dune_config *config);
extern void __dune_go_dune(int fd, struct dune_config *config);

// assembly routine for handling vsyscalls
extern char __dune_vsyscall_page;

// fault handling

/*
 * We use the same general GDT layout as Linux so that can we use
 * the same syscall MSR values. In practice only code segments
 * matter, since ia-32e mode ignores most of segment values anyway,
 * but just to be extra careful we match data as well.
 */
#define GD_KT		0x10
#define GD_KD		0x18
#define GD_UD		0x28
#define GD_UT		0x30
#define GD_TSS		0x38
#define GD_TSS2		0x40
#define NR_GDT_ENTRIES	9

struct dune_tf {
	/* manually saved, arguments */
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;

	/* saved by C calling conventions */
	uint64_t rbx;
	uint64_t rbp;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;

	/* system call number, ret */
	uint64_t rax;

	/* exception frame */
	uint32_t err;
	uint32_t pad1;
	uint64_t rip;
	uint16_t cs;
	uint16_t pad2[3];
	uint64_t rflags;
	uint64_t rsp;
	uint16_t ss;
	uint16_t pad3[3];
} __attribute__((packed));

#define ARG0(tf)        ((tf)->rdi)
#define ARG1(tf)        ((tf)->rsi)
#define ARG2(tf)        ((tf)->rdx)
#define ARG3(tf)        ((tf)->rcx)
#define ARG4(tf)        ((tf)->r8)
#define ARG5(tf)        ((tf)->r9)

typedef void (*dune_intr_cb) (struct dune_tf *tf);
typedef void (*dune_pgflt_cb) (uintptr_t addr, uint64_t fec,
			      struct dune_tf *tf);
typedef void (*dune_syscall_cb) (struct dune_tf *tf);

// XXX: Must match kern/dune.h
#define DUNE_SIGNAL_INTR_BASE 200

// vmpl initialization
int vmpl_init();
int vmpl_enter();
int vmpl_exit();

#endif /* __VMPL_H_ */
