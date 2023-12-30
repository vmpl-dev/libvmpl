#ifndef __VMPL_H_
#define __VMPL_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __GLIBC__
#include <asm/prctl.h>
#else
#include <sys/prctl.h>
#define ARCH_GET_FS			0x1003
#define ARCH_GET_GS			0x1004
#endif

#define MAX_LINE_LENGTH 256

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

#define KERNEL_CODE32   0x00cf9b000000ffff // [G], [D], L, AVL, [P], DPL=0, [1], [1], C, [R], [A]
#define KERNEL_CODE64   0x00af9b000000ffff // [G], D, [L], AVL, [P], DPL=0, [1], [1], C, [R], [A]
#define KERNEL_DATA     0x00cf93000000ffff // [G], [B], L, AVL, [P], DPL=0, [1], [0], E, [W], [A]
#define USER_CODE32     0x00cffb000000ffff // [G], [D], L, AVL, [P], DPL=3, [1], [1], C, [R], [A]
#define USER_DATA       0x00cff3000000ffff // [G], [D], L, AVL, [P], DPL=3, [1], [0], E, [W], [A]
#define USER_CODE64     0x00affb000000ffff // [G], D, [L], AVL, [P], DPL=3, [1], [1], C, [R], [A]
#define TSS             0x0080890000000000 // [G], B, L, AVL, [P], DPL=0, [0], [0], [0], [0], [0]
#define TSS2            0x0000000000000000 // [G], B, L, AVL, [P], DPL=0, [0], [0], [0], [0], [0]

#define VSYSCALL_ADDR 0xffffffffff600000UL

struct gdtr_entry {
    uint64_t limit_lo : 16;     // 段界限低16位
    uint64_t base : 24;         // 
    uint64_t type : 4;
    uint64_t s : 1;
    uint64_t dpl : 2;
    uint64_t p : 1;
    uint64_t limit_hi : 4;
    uint64_t avl : 1;
    uint64_t l : 1;
    uint64_t db : 1;
    uint64_t g : 1;
} __attribute__((packed));

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

typedef void (*dune_intr_cb) (struct dune_tf *tf);
typedef void (*dune_pgflt_cb) (uintptr_t addr, uint64_t fec, struct dune_tf *tf);
typedef void (*dune_syscall_cb) (struct dune_tf *tf);
typedef void (*sighandler_t)(int);

#define DUNE_SIGNAL_INTR_BASE 200

#ifdef __cplusplus
extern "C" {
#endif
extern int arch_prctl(int code, unsigned long *addr);
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

// dune routines for registering handlers
extern int dune_register_intr_handler(int vec, dune_intr_cb cb);
extern int dune_register_signal_handler(int signum, dune_intr_cb cb);
extern void dune_register_pgflt_handler(dune_pgflt_cb cb);
extern void dune_register_syscall_handler(dune_syscall_cb cb);

// fault handling
extern sighandler_t dune_signal(int sig, sighandler_t cb);
extern void dune_syscall_handler(struct dune_tf *tf);
extern void dune_trap_handler(int num, struct dune_tf *tf);

// vmpl initialization
extern int vmpl_enter(int argc, char *argv[]);
#ifdef __cplusplus
}
#endif

#define VMPL_ENTER                  \
	do                              \
	{                               \
		if (vmpl_enter(1, NULL)) 	\
		{                           \
			return 1;               \
		}                           \
	} while (0)

#endif /* __VMPL_H_ */
