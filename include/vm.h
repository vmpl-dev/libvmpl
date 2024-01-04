#ifndef __VMPL_VM_H_
#define __VMPL_VM_H_

#include "config.h"
#include "vma.h"

#include <stdbool.h>
#include <dict/dict.h>
#include <pthread.h>

/* Define beginning and end of VA space */
#define VA_START		((void *)0)
#define VA_END			((void *)-1)

/* Define maximum size of self-managed virtual memory area */
#define MAP_SIZE 		CONFIG_VMPL_VA_START

/* VMPL-VM Abstraction */
struct vmpl_vm_t {
	dict *vma_dict;
	fit_algorithm_t fit_algorithm;
	uint64_t va_start;
	uint64_t va_end;
	pthread_spinlock_t lock;
};

// VMPL-VM Low Level API
extern bool insert_vma(struct vmpl_vm_t *vm, struct vmpl_vma_t *vma);
extern struct vmpl_vma_t *find_vma(struct vmpl_vm_t *vm, uint64_t addr);
extern struct vmpl_vma_t *find_vma_intersection(struct vmpl_vm_t *vm, uint64_t start_addr, uint64_t end_addr);
extern bool remove_vma(struct vmpl_vm_t *vm, struct vmpl_vma_t *vma);
extern size_t get_vma_size(struct vmpl_vma_t *vma);
extern bool are_vmas_adjacent(struct vmpl_vma_t *vma1, struct vmpl_vma_t *vma2);
struct vmpl_vma_t *merge_vmas(struct vmpl_vma_t *vma1, struct vmpl_vma_t *vma2);
extern struct vmpl_vma_t *alloc_vma(struct vmpl_vm_t *vm, size_t size);

// VMPL-VM High Level API
extern int vmpl_vm_init(struct vmpl_vm_t *vm);
extern int vmpl_vm_exit(struct vmpl_vm_t *vm);
extern void vmpl_vm_stats(struct vmpl_vm_t *vm);
extern void vmpl_vm_test(struct vmpl_vm_t *vm);

#endif // __VMPL_VM_H_