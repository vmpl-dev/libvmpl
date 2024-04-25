#ifndef __VMPL_VM_H_
#define __VMPL_VM_H_

#include "config.h"
#include "vma.h"

#include <stdbool.h>
#include <dict/dict.h>
#include <pthread.h>

/* Define maximum size of self-managed virtual memory area */
#define MAP_SIZE 		CONFIG_VMPL_VA_START

/* VMPL-VM Abstraction */
struct vmpl_vm_t {
	dict *vma_dict;
	fit_algorithm_t fit_algorithm;
	uint64_t pkey;
	uint64_t va_start;
	uint64_t va_end;
	uintptr_t phys_limit;
	uintptr_t mmap_base;
	uintptr_t start_stack;
	pthread_spinlock_t lock;
};

// VMPL-VM Low Level API
extern bool insert_vma(struct vmpl_vm_t *vm, struct vmpl_vma_t *vma);
extern bool expand_vma(struct vmpl_vm_t *vm, struct vmpl_vma_t *vma, uint64_t new_end);
extern struct vmpl_vma_t *find_vma(struct vmpl_vm_t *vm, uint64_t addr);
extern struct vmpl_vma_t *find_vma_exact(struct vmpl_vm_t *vm, uint64_t addr);
extern struct vmpl_vma_t *find_vma_intersection(struct vmpl_vm_t *vm, uint64_t start_addr, uint64_t end_addr);
extern struct vmpl_vma_t *find_prev_vma(struct vmpl_vm_t *vm, struct vmpl_vma_t *vma);
extern struct vmpl_vma_t *find_next_vma(struct vmpl_vm_t *vm, struct vmpl_vma_t *vma);
extern bool remove_vma(struct vmpl_vm_t *vm, struct vmpl_vma_t *vma);
extern struct vmpl_vma_t *alloc_vma_range(struct vmpl_vm_t *vm, uint64_t va_start, size_t size);
static inline struct vmpl_vma_t *alloc_vma(struct vmpl_vm_t *vm, size_t size) {
	return alloc_vma_range(vm, vm->va_start, size);
}

// VMPL-VM High Level API
extern int vmpl_vm_init(struct vmpl_vm_t *vm);
extern int vmpl_vm_init_procmaps(struct vmpl_vm_t *vm);
extern int vmpl_vm_exit(struct vmpl_vm_t *vm);
extern void vmpl_vm_dump(struct vmpl_vm_t *vm);
extern void vmpl_vm_stats(struct vmpl_vm_t *vm);
#ifdef CONFIG_VMPL_TEST
extern void vmpl_vm_test(struct vmpl_vm_t *vm);
#else
static inline void vmpl_vm_test(struct vmpl_vm_t *vm) {}
#endif

#endif // __VMPL_VM_H_