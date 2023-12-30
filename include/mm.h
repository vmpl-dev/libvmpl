#ifndef __VMPL_VM_H_
#define __VMPL_VM_H_

#include "sys.h"
#include "pgtable.h"

// virtual memory

#define vmpl_va_to_pa(va)	pgtable_va_to_pa(va)

#define PERM_NONE  	    0	    /* no access */
#define PERM_R		    0x0001	/* read permission */
#define PERM_W		    0x0002	/* write permission */
#define PERM_X		    0x0004	/* execute permission */
#define PERM_U		    0x0008	/* user-level permission */
#define PERM_UC		    0x0010  /* make uncachable */
#define PERM_COW	    0x0020	/* COW flag */
#define PERM_USR1	    0x1000  /* User flag 1 */
#define PERM_USR2	    0x2000  /* User flag 2 */
#define PERM_USR3	    0x3000  /* User flag 3 */
#define PERM_BIG	    0x0100	/* Use large pages */
#define PERM_BIG_1GB	0x0200	/* Use large pages (1GB) */

// Helper Macros
#define PERM_SCODE	(PERM_R | PERM_X)
#define PERM_STEXT	(PERM_R | PERM_W)
#define PERM_SSTACK	PERM_STEXT
#define PERM_UCODE	(PERM_R | PERM_U | PERM_X)
#define PERM_UTEXT	(PERM_R | PERM_U | PERM_W)
#define PERM_USTACK	PERM_UTEXT

#define vmpl_flush_tlb_one  flush_tlb_one
#define vmpl_flush_tlb      flush_tlb

#define CR3_NOFLUSH	(1UL << 63)

/* Define beginning and end of VA space */
#define VA_START		((void *)0)
#define VA_END			((void *)-1)

enum {
	CREATE_NONE = 0,
	CREATE_NORMAL = 1,
	CREATE_BIG = 2,
	CREATE_BIG_1GB = 3,
};

struct perm_map_t {
		int perm_flag;
		pte_t pte_flag;
};

struct map_phys_data_t {
	pte_t perm;
	unsigned long va_base;
	unsigned long pa_base;
};

extern int vmpl_fd;
extern int vmpl_vm_map_phys(pte_t *root, void *va, size_t len, void *pa, int perm);
extern int vmpl_vm_map_pages(pte_t *root, void *va, size_t len, int perm);
extern int vmpl_vm_insert_page(pte_t *root, void *va, struct page *pg, int perm);
extern struct page * vmpl_vm_lookup_page(pte_t *root, void *va);
extern int vmpl_vm_lookup(pte_t *root, void *va, int create, pte_t **pte_out);

typedef int (*page_walk_cb)(const void *arg, pte_t *ptep, void *va);
extern int vmpl_vm_page_walk(pte_t *root, void *start_va, void *end_va,
			    page_walk_cb cb, const void *arg);

extern void *vmpl_vm_mmap(pte_t *root, void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);
extern void vmpl_vm_unmap(pte_t *root, void *va, size_t len);
extern void *vmpl_vm_mremap(pte_t *root, void *old_address, size_t old_size,
					 size_t new_size, int flags, void *new_address);
extern int vmpl_vm_mprotect(pte_t *root, void *va, size_t len, int perm);

extern pte_t * vmpl_vm_clone(pte_t *root);
extern void vmpl_vm_free(pte_t *root);
extern void vmpl_vm_default_pgflt_handler(uintptr_t addr, uint64_t fec);

/* mmap */
struct vmpl_vm_t {
	uint64_t heap_start;
	uint64_t heap_end;
	uint64_t linear_start;
	uint64_t linear_end;
	uint64_t mmap_start;
	uint64_t mmap_end;
	uint64_t stack_start;
	uint64_t stack_end;
};

#define is_vmpl_vm_heap(vaddr, vmpl_vm) \
	((vaddr) >= (vmpl_vm)->heap_start && (vaddr) < (vmpl_vm)->heap_end)
#define is_vmpl_vm_linear(vaddr, vmpl_vm) \
	((vaddr) >= (vmpl_vm)->linear_start && (vaddr) < (vmpl_vm)->linear_end)
#define is_vmpl_vm_mmap(vaddr, vmpl_vm) \
	((vaddr) >= (vmpl_vm)->mmap_start && (vaddr) < (vmpl_vm)->mmap_end)
#define is_vmpl_vm_stack(vaddr, vmpl_vm) \
	((vaddr) >= (vmpl_vm)->stack_start && (vaddr) < (vmpl_vm)->stack_end)

extern int vmpl_vm_init(struct vmpl_vm_t *vmpl_vm);

#endif