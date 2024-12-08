#ifndef __VMPL_MM_H_
#define __VMPL_MM_H_

#include "pgtable.h"
#include "vm.h"

#include <sys/mman.h>
#include <pthread.h>
// virtual memory

#define vmpl_va_to_pa(va)	pgtable_va_to_pa(va)

// pkru register
#define PKRU_KEY_SHIFT	0
#define PKRU_KEY_MASK	0x3
#define PKRU_KEY_NONE	0x0
#define PKRU_KEY_ALL	0x3

#define SECURE_DOMAIN	0x0000000000000003UL
#define NORMAL_DOMAIN	0x0000000000000000UL
#define switch_to(domain)	wrpkru(domain)

#define vmpl_flush_tlb_one  flush_tlb_one
#define vmpl_flush_tlb      flush_tlb

#define VMPL_VM_MAP_PHYS_FMT	"start = 0x%lx, end = 0x%lx, perm = 0x%lx"
#define VMPL_VM_MAP_PAGES_FMT	"start = 0x%lx, end = 0x%lx, perm = 0x%lx"
#define VMPL_VM_MMAP_FMT		"start = 0x%lx, end = 0x%lx, perm = 0x%lx, flags = 0x%lx, fd = %d, offset = 0x%lx"
#define VMPL_VM_MREMAP_FMT		"old_start = 0x%lx, old_end = 0x%lx, new_start = 0x%lx, new_end = 0x%lx, perm = 0x%lx"
#define VMPL_VM_MUNMAP_FMT		"start = 0x%lx, end = 0x%lx"
#define VMPL_VM_MPROTECT_FMT	"start = 0x%lx, end = 0x%lx, prot = 0x%lx"
#define VMPL_VM_CLONE_FMT		"start = 0x%lx, end = 0x%lx, prot = 0x%lx, path = 0x%lx"
#define VMPL_VM_PKEY_MPROTECT_FMT	"start = 0x%lx, end = 0x%lx, prot = 0x%lx, pkey = %d"

struct perm_map_t {
		int perm_flag;
		pte_t pte_flag;
};

struct prot_map_t {
		int prot_flag;
		pte_t pte_flag;
};

struct map_phys_data_t {
	pte_t perm;
	unsigned long va_base;
	unsigned long pa_base;
};

struct mremap_arg_t {
	pte_t *root;
	void *old_address;
	size_t old_size;
	size_t new_size;
	int prot;
	int flags;
	void *new_address;
};

typedef uintptr_t phys_addr_t;
typedef uintptr_t virt_addr_t;

struct vmpl_mm_t {
	struct vmpl_vm_t vmpl_vm;
	bool initialized;
	pthread_mutex_t lock;
};

extern struct vmpl_mm_t vmpl_mm;
extern long dune_vm_default_pgflt_handler(uintptr_t addr, uint64_t fec);
extern long vmpl_mm_default_pgflt_handler(uintptr_t addr, uint64_t fec);
extern int vmpl_mm_init(struct vmpl_mm_t *mm);
extern int vmpl_mm_exit(struct vmpl_mm_t *mm);
extern void vmpl_mm_stats(struct vmpl_mm_t *mm);
#ifdef CONFIG_VMPL_TEST
extern void vmpl_mm_test(struct vmpl_mm_t *mm);
#else
static inline void vmpl_mm_test(struct vmpl_mm_t *mm) {}
#endif

int setup_mm();
#endif