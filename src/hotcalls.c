#include <errno.h>
#include <sys/syscall.h>
#include <asm-generic/unistd.h>
#include <hotcalls/hotcalls.h>
#include "vmpl.h"

// Define the maximum number of system calls
#define MAX_SYSCALLS __NR_syscalls

// Define the hotcalls bitmap
static uint64_t hotcalls_bitmap[MAX_SYSCALLS / 64 + 1] = { 0 };

// Register a system call as a hotcall
void register_hotcall(int syscall) {
	if (syscall >= 0 && syscall < MAX_SYSCALLS) {
		uint64_t mask = 1ULL << (syscall % 64);
		hotcalls_bitmap[syscall / 64] |= mask;
	}
}

// Unregister a system call as a hotcall
void unregister_hotcall(int syscall) {
	if (syscall >= 0 && syscall < MAX_SYSCALLS) {
		uint64_t mask = ~(1ULL << (syscall % 64));
		hotcalls_bitmap[syscall / 64] &= mask;
	}
}

// Check if a system call is a hotcall
bool is_hotcall(int syscall) {
	if (syscall >= 0 && syscall < MAX_SYSCALLS) {
		uint64_t mask = 1ULL << (syscall % 64);
		return (hotcalls_bitmap[syscall / 64] & mask) != 0;
	}
	return false;
}

int vmpl_hotcalls_call(struct dune_tf *tf)
{
    hotcall_args_t args = {
        .sysnr = tf->rax,
        .rdi = tf->rdi,
        .rsi = tf->rsi,
        .rdx = tf->rdx,
        .r10 = tf->rcx,
        .r8 = tf->r8,
        .r9 = tf->r9,
    };

	if (!is_hotcall(tf->rax)) {
		return -ENOSYS;
	}

	return hotcalls_call(&args);
}
