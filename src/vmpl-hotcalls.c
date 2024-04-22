#include <errno.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <asm-generic/unistd.h>
#include <hotcalls/hotcalls.h>
#include "vmpl.h"

// Define the maximum number of system calls
#define MAX_SYSCALLS __NR_syscalls

// Define the hotcalls bitmap
uint64_t *hotcalls_bitmap;

int init_hotcalls(void) {
	hotcalls_bitmap = (uint64_t *)malloc((MAX_SYSCALLS / 64 + 1) * sizeof(uint64_t));
	if (!hotcalls_bitmap) {
		return -ENOMEM;
	}
	memset(hotcalls_bitmap, 0, (MAX_SYSCALLS / 64 + 1) * sizeof(uint64_t));
	return 0;
}

// Register a system call as a hotcall
void register_hotcall(int syscall) {
	if (!hotcalls_bitmap) {
		init_hotcalls();
	}
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

int vmpl_hotcalls_callv(long nr, ...)
{
	va_list args;
	hotcall_args_t hotcall_args = {
		.sysnr = nr,
	};

	va_start(args, nr);
	hotcall_args.rdi = va_arg(args, long);
	hotcall_args.rsi = va_arg(args, long);
	hotcall_args.rdx = va_arg(args, long);
	hotcall_args.r10 = va_arg(args, long);
	hotcall_args.r8 = va_arg(args, long);
	hotcall_args.r9 = va_arg(args, long);
	va_end(args);

	if (!is_hotcall(nr)) {
		return -ENOSYS;
	}

	if (!hotcalls_initialized()) {
		return -ENOSYS;
	}

	return hotcalls_call(&hotcall_args);
}