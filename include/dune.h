#ifndef __DUNE_H_
#define __DUNE_H_

#include "vmpl.h"
#include "apic.h"
#include "mm.h"

#ifdef LIBDUNE
#define PTE_ADDR            pte_addr

typedef pte_t ptent_t;

static inline unsigned long dune_get_ticks(void)
{
	unsigned int a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((unsigned long) a) | (((unsigned long) d) << 32);
}

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
extern int dune_printf(const char *fmt, ...);
extern void * dune_mmap(void *addr, size_t length, int prot,
                        int flags, int fd, off_t offset);
extern void dune_die(void);

extern int dune_vm_mprotect(ptent_t *root, void *va, size_t len, int perm);
extern int dune_vm_map_phys(ptent_t *root, void *va, size_t len, void *pa, int perm);
extern int dune_vm_map_pages(ptent_t *root, void *va, size_t len, int perm);
extern void dune_vm_unmap(ptent_t *root, void *va, size_t len);
extern int dune_vm_lookup(ptent_t *root, void *va, int create, ptent_t **pte_out);

extern int dune_vm_insert_page(ptent_t *root, void *va, struct page *pg, int perm);
extern struct page * dune_vm_lookup_page(ptent_t *root, void *va);

extern ptent_t * dune_vm_clone(ptent_t *root);
extern void dune_vm_free(ptent_t *root);
extern void dune_vm_default_pgflt_handler(uintptr_t addr, uint64_t fec);

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
#else
#define ptent_t             pte_t
#define PTE_ADDR            pte_addr
#define load_cr3            pgtable_load_cr3
#define dune_flush_tlb      flush_tlb
#define dune_flush_tlb_one  flush_tlb_one
#define dune_printf         printf
#define dune_puts           puts
#define dune_mmap           mmap
#define dune_die            exit
#define dune_get_ticks      rdtsc

#define dune_fd             vmpl_fd

#define dune_enter()          vmpl_enter(1, NULL)
#define dune_init_and_enter() vmpl_enter(1, NULL)

#define dune_apic_ipi       apic_send_ipi
#define dune_apic_eoi       apic_eoi
#define dune_apic_init_rt_entry apic_init_rt_entry
#define dune_apic_id_for_cpu    apic_get_id_for_cpu
#define dune_apic_send_ipi      apic_send_ipi

#define dune_va_to_pa       pgtable_va_to_pa
#define dune_vm_mprotect	vmpl_vm_mprotect
#define dune_vm_map_phys	vmpl_vm_map_phys
#define dune_vm_map_pages	vmpl_vm_map_pages
#define dune_vm_unmap 		vmpl_vm_munmap
#define dune_vm_lookup		vmpl_vm_lookup

#define dune_vm_insert_page	vmpl_vm_insert_page
#define dune_vm_lookup_page	vmpl_vm_lookup_page

#define dune_vm_clone		vmpl_vm_clone
#define dune_vm_free		vmpl_vm_free
#define dune_vm_default_pgflt_handler	vmpl_mm_default_pgflt_handler

#define dune_vm_page_walk	vmpl_vm_page_walk
#endif
#endif