/**
 * @brief A syscall filtering mechanism to allow only a subset of syscalls to be forwarded to the guest OS
 * This is useful for implementing a syscall interposition mechanism in the lower VMPL, where the lower VMPL
 * can intercept and handle certain syscalls, and forward the rest to the guest OS.
 */

#ifndef __SYS_FILTER_H__
#define __SYS_FILTER_H__

#include <stdbool.h>

struct syscall_filter {
	bool (*filter)(struct dune_tf *tf);
	struct syscall_filter *next;
};

bool register_syscall_filter(bool (*filter)(struct dune_tf *tf));
bool apply_syscall_filters(struct dune_tf *tf);
bool remove_syscall_filter(bool (*filter)(struct dune_tf *tf));
void clear_syscall_filters();

#endif