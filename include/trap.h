#ifndef __TRAP_H_
#define __TRAP_H_

#include <stdint.h>

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

struct pf_err_code {
        uint32_t p : 1;
        uint32_t wr : 1;
        uint32_t us : 1;
        uint32_t rsvd : 1;
        uint32_t id : 1;
        uint32_t pk : 1;
        uint32_t ss : 1;
        uint32_t reserved : 24;
	uint32_t rmp : 1;
} __attribute__((packed));

#define PF_ERR_P       0x1
#define PF_ERR_WR      0x2
#define PF_ERR_US      0x4
#define PF_ERR_ID      0x10
#define PF_ERR_PK      0x20
#define PF_ERR_SS      0x40
#define PF_ERR_RMP     0x80

#endif