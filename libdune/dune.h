#ifndef __DUNE_H_
#define __DUNE_H_

#include <vmpl/vmpl.h>
#include <vmpl/pgtable.h>

#define PTE_ADDR            pte_addr

typedef pte_t ptent_t;

static inline void dune_flush_tlb_one(unsigned long addr)
{
	asm ("invlpg (%0)" :: "r" (addr) : "memory");
}

static inline void dune_flush_tlb(void)
{
	asm ("mov %%cr3, %%rax\n"
	     "mov %%rax, %%cr3\n" ::: "rax");
}

// virtual memory

extern void load_cr3(uint64_t cr3);

extern void dune_apic_ipi(uint32_t dest, uint32_t vector);
extern void dune_apic_eoi(void);
extern void dune_apic_init_rt_entry(void);
extern uint32_t dune_apic_id_for_cpu(uint32_t cpu, bool *error);
extern void dune_apic_send_ipi(uint8_t vector, uint32_t dest_apic_id);

extern uint64_t dune_va_to_pa(uint64_t va);
extern int dune_vm_mprotect(ptent_t *root, void *va, size_t len, int perm);
extern int dune_vm_map_phys(ptent_t *root, void *va, size_t len, void *pa, int perm);
extern int dune_vm_map_pages(ptent_t *root, void *va, size_t len, int perm);
extern void dune_vm_unmap(ptent_t *root, void *va, size_t len);
extern int dune_vm_lookup(ptent_t *root, void *va, int create, ptent_t **pte_out);

extern int dune_vm_insert_page(ptent_t *root, void *va, struct page *pg, int perm);
extern struct page * dune_vm_lookup_page(ptent_t *root, void *va);

extern ptent_t * dune_vm_clone(ptent_t *root);
extern void dune_vm_free(ptent_t *root);

extern int dune_vm_page_walk(ptent_t *root, void *start_va, void *end_va,
			    page_walk_cb cb, const void *arg);

// entry routines

extern int dune_init(bool map_full);
extern int dune_enter();

/**
 * dune_init_and_enter - initializes libdune and enters "Dune mode"
 * 
 * This is a simple initialization routine that handles everything
 * in one go. Note that you still need to call dune_enter() in
 * each new forked child or thread.
 * 
 * Returns 0 on success, otherwise failure.
 */
static inline int dune_init_and_enter(void)
{
	int ret;
	
	if ((ret = dune_init(1)))
		return ret;
	
	return dune_enter();
}
#endif