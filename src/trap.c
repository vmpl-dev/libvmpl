/*
 * trap.c - x86 fault handling
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "config.h"
#include "sys.h"
#include "mm.h"
#include "vmpl.h"
#include "log.h"
#include "vmpl-core.h"

/**
 * @brief  Exception messages
 * @note   This is used to print the exception message when an exception occurs.
 */
static const char *exceptions[] = {
	[0] = "Divide-by-zero Error",
	[1] = "Debug Exception",
	[2] = "Non-maskable Interrupt",
	[3] = "Breakpoint Exception",
	[4] = "Overflow Exception",
	[5] = "Bound Range Exceeded Exception",
	[6] = "Invalid Opcode Exception",
	[7] = "Device Not Available Exception",
	[8] = "Double Fault Exception",
	[9] = "Coprocessor Segment Overrun",
	[10] = "Invalid TSS Exception",
	[11] = "Segment Not Present Exception",
	[12] = "Stack Fault Exception",
	[13] = "General Protection Exception",
	[14] = "Page Fault Exception",
	[15] = "Reserved Exception",
	[16] = "x87 Floating-Point Exception",
	[17] = "Alignment Check Exception",
	[18] = "Machine Check Exception",
	[19] = "SIMD Floating-Point Exception",
	[20] = "Reserved",
	[21] = "Control-Protection Exception",
	[22 ... 27] = "Reserved Exception",
	[28] = "Hypervisor Injection Exception",
	[29] = "VMM Communication Exception",
	[30] = "Security Exception",
	[31 ... 255 ] = "Reserved Exception",
};

static dune_syscall_cb syscall_cb;
static dune_pgflt_cb pgflt_cb;
static dune_intr_cb intr_cbs[IDT_ENTRIES];

void dune_vm_default_pgflt_handler(struct dune_tf *tf) {
	if (pgflt_cb) {
		pgflt_cb(read_cr2(), tf->err, tf);
	} else {
		printf("unhandled page fault %lx %lx\n", read_cr2(), tf->err);
		dune_dump_trap_frame(tf);
		exit(EXIT_FAILURE);
	}
}

int dune_register_intr_handler(int vec, dune_intr_cb cb)
{
	if (vec >= IDT_ENTRIES || vec < 0)
		return -EINVAL;

	intr_cbs[vec] = cb;
	return 0;
}

int dune_register_signal_handler(int signum, dune_intr_cb cb)
{
	return dune_register_intr_handler(DUNE_SIGNAL_INTR_BASE + signum, cb);
}

void dune_register_syscall_handler(dune_syscall_cb cb)
{
	syscall_cb = cb;
}

void dune_register_pgflt_handler(dune_pgflt_cb cb)
{
	pgflt_cb = cb;
	dune_register_intr_handler(T_PF, dune_vm_default_pgflt_handler);
}

#ifdef CONFIG_VMPL_DEBUG
#ifdef CONFIG_STACK_TRACE
static bool addr_is_mapped(void *va)
{
    int ret;
    pte_t *pte;

    ret = vmpl_vm_lookup(pgroot, va, CREATE_NONE, &pte);
    if (ret)
        return 0;

    if (!(*pte & PTE_P))
        return 0;

    return 1;
}

#define STACK_DEPTH 12

static void dune_dump_stack(struct dune_tf *tf)
{
    int i;
    unsigned long *sp = (unsigned long *) tf->rsp;

    // we use printf() because this might
    // have to work even if libc doesn't.
    printf("dune: Dumping Stack Contents...\n");
    for (i = 0; i < STACK_DEPTH; i++) {
        if (!addr_is_mapped(&sp[i])) {
            printf("dune: reached unmapped addr\n");
            break;
        }
        printf("dune: RSP%+-3d 0x%016lx\n", i * sizeof(long),
               sp[i]);
    }
}
#else
static void dune_dump_stack(struct dune_tf *tf) { }
#endif

static void dune_hexdump(void *x, int len)
{
	unsigned char *p = x;

	while (len--)
		printf("%.2x ", *p++);

	printf("\n");
}

static void dump_ip(struct dune_tf *tf)
{
	unsigned char *p = (void *)tf->rip;
	int len = 20;

	printf("dune: code before IP\t");
	dune_hexdump(p - len, len);

	printf("dune: code at IP\t");
	dune_hexdump(p, len);
}

void dune_dump_trap_frame(struct dune_tf *tf)
{
	// we use printf() because this might
	// have to work even if libc doesn't.
	printf("dune: --- Begin Trap Dump ---\n");
	printf("dune: RIP 0x%016lx\n", tf->rip);
	printf("dune: CS 0x%02x SS 0x%02x\n", tf->cs, tf->ss);
	printf("dune: ERR 0x%08x RFLAGS 0x%08lx\n", tf->err, tf->rflags);
	printf("dune: RAX 0x%016lx RCX 0x%016lx\n", tf->rax, tf->rcx);
	printf("dune: RDX 0x%016lx RBX 0x%016lx\n", tf->rdx, tf->rbx);
	printf("dune: RSP 0x%016lx RBP 0x%016lx\n", tf->rsp, tf->rbp);
	printf("dune: RSI 0x%016lx RDI 0x%016lx\n", tf->rsi, tf->rdi);
	printf("dune: R8  0x%016lx R9  0x%016lx\n", tf->r8, tf->r9);
	printf("dune: R10 0x%016lx R11 0x%016lx\n", tf->r10, tf->r11);
	printf("dune: R12 0x%016lx R13 0x%016lx\n", tf->r12, tf->r13);
	printf("dune: R14 0x%016lx R15 0x%016lx\n", tf->r14, tf->r15);
	dune_dump_stack(tf);
	dump_ip(tf);
	printf("dune: --- End Trap Dump ---\n");
}
#else
void dune_dump_trap_frame(struct dune_tf *tf) { }
#endif

void dune_passthrough_syscall(struct dune_tf *tf)
{
	int ret;
	ret = syscall(tf->rax, tf->rdi, tf->rsi, tf->rdx, tf->rcx, tf->r8, tf->r9);
	tf->rax = ret;
}

void dune_syscall_handler(struct dune_tf *tf)
{
	if (syscall_cb) {
		log_debug("dune: handling syscall %ld", tf->rax);
		syscall_cb(tf);
	} else {
		log_err("dune: missing handler for syscall %ld", tf->rax);
		dune_dump_trap_frame(tf);
		exit(EXIT_FAILURE);
	}
}

void dune_trap_handler(int num, struct dune_tf *tf)
{
	if (intr_cbs[num]) {
		intr_cbs[num](tf);
		return;
	} else {
		long ret = syscall(ULONG_MAX, num, (unsigned long)tf);
		if (ret != 0) {
			log_err("Unable to handle trap %d, error code %d", num, ret);
			dune_dump_trap_frame(tf);
			exit(EXIT_FAILURE);
		}
	}
}