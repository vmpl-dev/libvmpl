// Contents: syscall related functions
// This file is not used in the project
#ifndef __VMPL_SYSCALL_H_
#define __VMPL_SYSCALL_H_
#pragma once

#ifndef __ASSEMBLY__
#include "vmpl.h"

struct syscall_args_t {
    long a0, a1, a2, a3, a4, a5;
} __attribute__((packed));

long __vmpl_syscall(long sys_nr, struct syscall_args_t *args);
#ifdef CONFIG_DUNE_BOOT
int setup_syscall(bool map_full);
void setup_vsyscall(void);
#else
static inline int setup_syscall(bool map_full) { return 0; }
static inline void setup_vsyscall(void) {}
#endif
#else
.macro VMPL_SYSCALL
    push %r9
    push %r8
    push %r10
    push %rdx
    push %rsi
    push %rdi
    mov %rax, %rdi
    mov %rsp, %rsi
    call __vmpl_syscall
    pop %rdi
    pop %rsi
    pop %rdx
    pop %r10
    pop %r8
    pop %r9
.endm
#endif
#endif