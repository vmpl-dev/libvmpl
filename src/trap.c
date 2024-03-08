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
#include <assert.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "config.h"
#include "mmu-x86.h"
#include "sys.h"
#include "page.h"
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
	ret = syscall(tf->rax, tf->rdi, tf->rsi, tf->rdx, tf->r10, tf->r8, tf->r9);
	tf->rax = ret;
}

#ifdef CONFIG_VMPL_MM
/**
 * @brief System call handler
 * @note This function is called when a system call is made.
 * This handler intercepts the system call and calls the appropriate handler.
 * We intercept mmap, munmap, mprotect, pkey_mprotect, mremap, and clone system calls.
 * We forward all other system calls to the guest OS.
 * If the system call is not handled, then the program exits.
 * @param tf trap frame
 */
void dune_syscall_handler(struct dune_tf *tf)
{
	if (syscall_cb) {
		log_debug("dune: handling syscall %ld", tf->rax);
		switch (tf->rax) {
		case __NR_mmap:
			mmap(tf->rdi, tf->rsi, tf->rdx, tf->r10, tf->r8, tf->r9);
			break;
		case __NR_munmap:
			munmap(tf->rdi, tf->rsi);
			break;
		case __NR_mprotect:
			mprotect(tf->rdi, tf->rsi, tf->rdx);
			break;
		case __NR_pkey_mprotect:
			pkey_mprotect(tf->rdi, tf->rsi, tf->rdx, tf->r10);
			break;
		case __NR_mremap:
			mremap(tf->rdi, tf->rsi, tf->rdx, tf->r10, tf->r8);
			break;
		case __NR_pkey_alloc:
			pkey_alloc(tf->rdi, tf->rsi);
			break;
		case __NR_pkey_free:
			pkey_free(tf->rdi);
			break;
		case __NR_clone:
			clone(tf->rdi, tf->rsi, tf->rdx, tf->r10, tf->r8, tf->r9);
			break;
		defult:
			syscall_cb(tf);
		break;
		}
	} else {
		log_err("dune: missing handler for syscall %ld", tf->rax);
		dune_dump_trap_frame(tf);
		exit(EXIT_FAILURE);
	}
}

/**
 * @brief Pre page fault handler
 * @note This function is called when a page fault occurs. We handle the page fault
 * by duplicating the page if the page is a COW page or allocating the page if the page is lazy allocated.
 * If the page fault is not handled, then we call the dune page fault callback.
 * If the dune page fault callback is not registered, then we return -1.
 * If the page fault is handled, then we return 0.
 * @param tf trap frame
 * @return int 0 if the page fault is handled, -1 if the page fault is not handled
 */
static int dune_pre_pf_handler(struct dune_tf *tf)
{
	uint64_t fec = tf->err;

	// Reject I/D, PK, RMP, and SS faults
	if (fec & (PF_ERR_ID | PF_ERR_PK | PF_ERR_RMP | PF_ERR_SS)) {
		goto failed;
	}

	uintptr_t addr = read_cr2();

	if (fec & PF_ERR_P) {
#if 0
		// If the page is a COW page, then we need to duplicate the page.
		if (fec & (PF_ERR_WR | PF_ERR_RSVD)) {
			if(dune_vm_default_pgflt_handler(addr, fec) == 0)
				goto exit;
		}

		// If the dune page fault callback is registered, then call the callback.
		if (pgflt_cb) {
			pgflt_cb(addr, fec, tf);
			goto exit;
		}
#endif
	} else {
		// If the page is lazy allocated, then we need to allocate the page.
		if(vmpl_mm_default_pgflt_handler(addr, fec) == 0)
			goto exit;
	}

failed:
	return -1;
exit:
	return 0;
}

/**
 * @brief Post page fault handler
 * @note This function is called after a page fault occurs. We handle the page fault
 * by marking the page as a VMPL page if the page fault is handled.
 * @param tf trap frame
 * @return int 0 if the page fault is handled, -1 if the page fault is not handled
 */
static int dune_post_pf_handler(struct dune_tf *tf)
{
	int ret;
	pte_t *ptep, *child_ptep;
	uint64_t fec = tf->err;
	uintptr_t addr = read_cr2();
	// Find the page table entry for the faulting address in the host sthread
	ret = pgtable_lookup(pgroot, addr, CREATE_NONE, &ptep);
	if (ret != 0)
		return -1;

	// Mark the page as a VMPL page if the page fault is handled
	uint64_t paddr = pte_addr(*ptep);
	if (!vmpl_page_is_from_pool(paddr))
		vmpl_page_mark_addr(paddr);

	// If the page fault is handled for another sthread, then copy the page table entry
	uint64_t cr3 = read_cr3();
	pte_t *pgd = pgtable_pa_to_va(pte_addr(cr3));
	// Find the page table entry for the faulting address
	if (pgd != pgroot) {
		// Find the page table entry for the faulting address in the child sthread
		ret = pgtable_lookup(pgd, addr, CREATE_NORMAL, &child_ptep);
		if (ret != 0)
			return -1;
		// Copy the page table entry from the host to the child
		*child_ptep = *ptep;
		// Mark the page as a VMPL page in the child sthread
		vmpl_page_get_addr(paddr);
		// Invalidate the TLB
		vmpl_flush_tlb_one(addr);
	}

	return 0;
}

/**
 * @brief Pre-trap handler
 * If the trap is not a page fault, then we do not need to handle the trap.
 * We can just forward the trap to the guest OS.
 * @param num trap number
 * @param tf trap frame
 * @return int 0 if the trap is handled, -1 if the trap is not handled
 */
static int dune_pre_trap_handler(int num, struct dune_tf *tf)
{
	int ret;

	switch (num) {
	case T_PF:
		ret = dune_pre_pf_handler(tf);
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
}

/**
 * @brief Post-trap handler
 * If the trap is not a page fault, then we do not need to do anything.
 * We can just return back to the program.
 * @param num trap number
 * @param tf trap frame
 * @return int 0 if the trap is handled, -1 if the trap is not handled
 */
static int dune_post_trap_handler(int num, struct dune_tf *tf)
{
	int ret;
	switch (num) {
	case T_PF:
		ret = dune_post_pf_handler(tf);
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

/**
 * @brief Trap handler for system calls and interrupts
 * @note This function is called when a interrupt or exception occurs.
 * This handler intercepts the interrupt or exception and calls the appropriate handler.
 * We intercept page faults and forward all other interrupts and exceptions to the guest OS.
 * If the interrupt or exception is not handled, then the program exits.
 * @param num trap number
 * @param tf trap frame
 */
void dune_trap_handler(int num, struct dune_tf *tf)
{
	if (intr_cbs[num]) {
		intr_cbs[num](tf);
		return;
	}

	// Call the pre-trap handler before handling the trap in the guest OS
	int ret = dune_pre_trap_handler(num, tf);
	if (ret == 0)
		goto exit;

	// Forward the trap to the guest OS if the pre-trap handler does not handle the trap
	ret = syscall(ULONG_MAX, num, (unsigned long)tf);
	if (ret != 0)
		goto failed;

	// Call the post-trap handler after handling the trap in the guest OS
	ret = dune_post_trap_handler(num, tf);
	if (ret == 0)
		goto exit;

failed:
	// If the trap is not handled by the pre-trap handler, the guest OS, or 
	// the post-trap handler, then dump the trap frame and exit.
	log_err("Unable to handle trap %d, error code %d", num, ret);
	dune_dump_trap_frame(tf);
	exit(EXIT_FAILURE);
exit:
	return;
}
#else
/**
 * @brief Default system call handler
 * @note This function forwards all system calls to the guest OS.
 * @param tf trap frame
 */
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

/**
 * @brief Default page fault handler
 * @note This function forwards all interrupts and exceptions to the guest OS.
 * @param tf trap frame
 */
void dune_trap_handler(int num, struct dune_tf *tf)
{
	if (intr_cbs[num]) {
		intr_cbs[num](tf);
		return;
	}

	if (syscall(ULONG_MAX, num, (unsigned long)tf) != 0) {
		log_err("dune: unable to handle trap %d", num);
		dune_dump_trap_frame(tf);
		exit(EXIT_FAILURE);
	}
}
#endif