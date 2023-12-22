#ifndef __VMPL_MM_H_
#define __VMPL_MM_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#include "pgtable.h"

struct vmpl_vm_t {
	uint64_t heap_start;
	uint64_t heap_end;
};

#define is_vmpl_vm(vaddr, vmpl_vm) \
	((vaddr) >= (vmpl_vm)->heap_start && (vaddr) < (vmpl_vm)->heap_end)

typedef int (*page_walk_cb)(const void *arg, pte_t *ptep, void *va);

#define dune_va_to_pa		vmpl_va_to_pa
#define dune_vm_page_walk	vmpl_vm_page_walk
#define dune_vm_clone 		vmpl_vm_clone

int vmpl_vm_init(struct vmpl_vm_t *vmpl_vm);
int vmpl_vm_page_walk(pte_t *root, void *start_va, void *end_va,
					  page_walk_cb cb, const void *arg);
int vmpl_vm_clone(pte_t *root);
void *vmpl_mmap(void *addr, size_t length, int prot, int flags, int fd,
				off_t offset);
void *vmpl_mremap(void *old_address, size_t old_size, size_t new_size,
				  int flags);
int vmpl_munmap(void *addr, size_t length);

#endif