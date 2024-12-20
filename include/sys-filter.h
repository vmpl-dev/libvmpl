/**
 * @brief A syscall filtering mechanism to allow only a subset of syscalls to be forwarded to the guest OS
 * This is useful for implementing a syscall interposition mechanism in the lower VMPL, where the lower VMPL
 * can intercept and handle certain syscalls, and forward the rest to the guest OS.
 */

#ifndef __SYS_FILTER_H__
#define __SYS_FILTER_H__

#include <stdbool.h>
#include "vmpl.h"

typedef enum {
	LOW,
	NORMAL,
	MEDIUM,
	HIGH
} filter_priority;

typedef void (*filter_error_handler)(struct pt_regs *tf);

struct syscall_filter {
	int syscall_number;
	bool (*filter)(struct pt_regs *tf);
	filter_priority priority;
	filter_error_handler error_handler;
	struct syscall_filter *next;
};

void init_syscall_filter(struct syscall_filter* filter);
bool register_syscall_filter(bool (*filter)(struct pt_regs *tf));
bool register_syscall_filter_single(struct syscall_filter *new_filter);
bool apply_syscall_filters(struct pt_regs *tf);
bool remove_syscall_filter(bool (*filter)(struct pt_regs *tf));
void clear_syscall_filters();

#endif