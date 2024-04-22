#ifndef __VMPL_H_
#define __VMPL_H_

#pragma once

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/ucontext.h>

#ifdef __GLIBC__
#include <asm/prctl.h>
#else
#include <sys/prctl.h>
#define ARCH_GET_FS			0x1003
#define ARCH_GET_GS			0x1004
#endif

#define MAX_LINE_LENGTH 256

typedef void (*sighandler_t)(int);

// utilities

static inline unsigned long dune_get_ticks(void)
{
	unsigned int a, d;
	asm volatile("rdtsc" : "=a"(a), "=d"(d));
	return ((unsigned long)a) | (((unsigned long)d) << 32);
}

extern int dune_printf(const char *fmt, ...);
extern void dune_die(void);
extern void *dune_mmap(void *addr, size_t length, int prot, int flags, int fd,
					   off_t offset);
extern sighandler_t dune_signal(int sig, sighandler_t cb);
extern unsigned long dune_get_user_fs(void);
extern void dune_set_user_fs(unsigned long fs_base);

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

#define ARG0(tf) ((tf)->rdi)
#define ARG1(tf) ((tf)->rsi)
#define ARG2(tf) ((tf)->rdx)
#define ARG3(tf) ((tf)->rcx)
#define ARG4(tf) ((tf)->r8)
#define ARG5(tf) ((tf)->r9)

typedef void (*dune_intr_cb) (struct dune_tf *tf);
typedef void (*dune_pgflt_cb) (uintptr_t addr, uint64_t fec, struct dune_tf *tf);
typedef void (*dune_syscall_cb) (struct dune_tf *tf);
typedef void (*sighandler_t)(int);

#define PF_ERR_P       0x1
#define PF_ERR_WR      0x2
#define PF_ERR_US      0x4
#define PF_ERR_RSVD    0x8
#define PF_ERR_ID      0x10
#define PF_ERR_PK      0x20
#define PF_ERR_SS      0x40
#define PF_ERR_RMP     0x80

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

extern void dune_pop_trap_frame(struct dune_tf *tf);
extern int dune_jump_to_user(struct dune_tf *tf);
extern void dune_ret_from_user(int ret) __attribute__((noreturn));
extern void dune_dump_trap_frame(struct dune_tf *tf);
extern void dune_passthrough_syscall(struct dune_tf *tf);

// ucontext support
extern void dune_getcontext(ucontext_t *ucp, struct dune_tf *tf);
extern void dune_setcontext(const ucontext_t *ucp, struct dune_tf *tf);

// syscall filtering
extern bool register_syscall_filter(bool (*filter)(struct dune_tf *tf));

// hotcall routines
int init_hotcalls(void);
void register_hotcall(int syscall);
void unregister_hotcall(int syscall);
bool is_hotcall(int syscall);
int vmpl_hotcalls_call(struct dune_tf *tf);

// elf helper functions
#include "elf.h"
struct dune_elf {
	int		fd;
	unsigned char	*mem;
	int		len;
	Elf64_Ehdr	hdr;
	Elf64_Phdr	*phdr;
	Elf64_Shdr	*shdr;
	char		*shdrstr;
	void		*priv;
};

#define PGSIZE 4096

typedef int (*dune_elf_phcb)(struct dune_elf *elf, Elf64_Phdr *phdr);
typedef int (*dune_elf_shcb)(struct dune_elf *elf, const char *sname,
		                     int snum, Elf64_Shdr *shdr);

extern int dune_elf_open(struct dune_elf *elf, const char *path);
extern int dune_elf_open_mem(struct dune_elf *elf, void *mem, int len);
extern int dune_elf_close(struct dune_elf *elf);
extern int dune_elf_dump(struct dune_elf *elf);
extern int dune_elf_iter_sh(struct dune_elf *elf, dune_elf_shcb cb);
extern int dune_elf_iter_ph(struct dune_elf *elf, dune_elf_phcb cb);
extern int dune_elf_load_ph(struct dune_elf *elf, Elf64_Phdr *phdr, off_t off);

// vmpl initialization
extern bool vmpl_booted;
extern int vmpl_init(bool map_full);
extern int vmpl_enter(int argc, char *argv[]);
/**
 * vmpl_init_and_enter - initializes libvmpl and enters "VMPL mode"
 * 
 * This is a simple initialization routine that handles everything
 * in one go. Note that you still need to call vmpl_enter() in
 * each new forked child or thread.
 * 
 * Returns 0 on success, otherwise failure.
 */
static inline int vmpl_init_and_enter(int argc, char *argv[])
{
	int ret;

	if ((ret = vmpl_init(1)))
		return ret;

	return vmpl_enter(argc, argv);
}

#define VMPL_ENTER                        \
	do                                    \
	{                                     \
		if (vmpl_init_and_enter(1, NULL)) \
		{                                 \
			return 1;                     \
		}                                 \
	} while (0)
#ifdef __cplusplus
}
#endif
#endif /* __VMPL_H_ */
