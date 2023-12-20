#ifndef _LIBVMPL_MM_H
#define _LIBVMPL_MM_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "config.h"
#include "sys.h"

#ifdef CONFIG_PGTABLE_LA57
typedef uint64_t pgd_t;
typedef uint64_t p4d_t;
typedef uint64_t pmd_t;
typedef uint64_t pud_t;
typedef uint64_t pte_t;
#else
typedef uint64_t pml4e_t;
typedef uint64_t pdpe_t;
typedef uint64_t pde_t;
typedef uint64_t pte_t;
#endif

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_DOWN(x) ((x) & ~(PAGE_SIZE - 1))
#define PAGE_MASK(x) ((x) & (PAGE_SIZE - 1))

#ifdef CONFIG_PGTABLE_LA57
#define P4D_PRESENT (1UL << 0)
#define PUD_PRESENT (1UL << 0)
#define PMD_PRESENT (1UL << 0)
#define PTE_PRESENT (1UL << 0)

#define P4D_BAD (1UL << 1)
#define PUD_BAD (1UL << 1)
#define PMD_BAD (1UL << 1)
#define PTE_BAD (1UL << 1)

#define pgd_index(va) (((unsigned long)(va) >> 39) & 0x1ff)
#define p4d_index(va) (((unsigned long)(va) >> 39) & 0x1ff)
#define pud_index(va) (((unsigned long)(va) >> 30) & 0x1ff)
#define pmd_index(va) (((unsigned long)(va) >> 21) & 0x1ff)
#define pte_index(va) (((unsigned long)(va) >> 12) & 0x1ff)

#define pgd_offset(pgd, va) ((pgd) + pgd_index(va))
#define p4d_offset(pgd, va) ((pgd) + p4d_index(va))
#define pud_offset(p4d, va) ((p4d) + pud_index(va))
#define pmd_offset(pud, va) ((pud) + pmd_index(va))
#define pte_offset(pmd, va) ((pmd) + pte_index(va))

#define pgd_none(pgd) (!(pgd & P4D_PRESENT))
#define p4d_none(p4d) (!(p4d & P4D_PRESENT))
#define pud_none(pud) (!(pud & PUD_PRESENT))
#define pmd_none(pmd) (!(pmd & PMD_PRESENT))
#define pte_none(pte) (!(pte & PTE_PRESENT))

#define pgd_bad(pgd) (pgd & P4D_BAD)
#define p4d_bad(p4d) (p4d & P4D_BAD)
#define pud_bad(pud) (pud & PUD_BAD)
#define pmd_bad(pmd) (pmd & PMD_BAD)
#define pte_bad(pte) (pte & PTE_BAD)

#define pgd_present(pgd) ((pgd) & 0x1)
#define p4d_present(p4d) ((p4d) & 0x1)
#define pud_present(pud) ((pud) & 0x1)
#define pmd_present(pmd) ((pmd) & 0x1)
#define pte_present(pte) ((pte) & 0x1)
#else
#define PML4E_PRESENT (1UL << 0)
#define PDPE_PRESENT  (1UL << 0)
#define PDE_PRESENT   (1UL << 0)
#define PTE_PRESENT   (1UL << 0)
#define PTE_WRITE   (1UL << 1)
#define PTE_USER    (1UL << 2)
#define PTE_ACCESSED (1UL << 5)
#define PTE_DIRTY    (1UL << 6)

#define PML4E_BAD (1UL << 1)
#define PDPE_BAD  (1UL << 1)
#define PDE_BAD   (1UL << 1)
#define PTE_BAD   (1UL << 1)

#define page_address(page) ((page) << 12)
#define pte_addr(pte) ((pte) & 0x0000fffffffff000UL)

#define pfn2page(pfn) ((pfn) << 12)
#define page2pfn(page) ((page) >> 12)

#define pml4_index(va) (((unsigned long)(va) >> 39) & 0x1ff)
#define pdp_index(va)  (((unsigned long)(va) >> 30) & 0x1ff)
#define pd_index(va)   (((unsigned long)(va) >> 21) & 0x1ff)
#define pt_index(va)   (((unsigned long)(va) >> 12) & 0x1ff)

#define pml4_deref(pml4)   __va(pte_addr(*pml4))
#define pdpe_deref(pdpe)   __va(pte_addr(*pdpe))
#define pde_deref(pde)     __va(pte_addr(*pde))
#define pte_deref(pte)     __va(pte_addr(*pte))

#define pml4_offset(pml4, va) ((pml4) + (pml4_index(va) << 3))
#define pdp_offset(pdp, va)   (pdpe_deref(pdp) + (pdp_index(va) << 3))
#define pd_offset(pd, va)     (pde_deref(pd) + (pd_index(va) << 3))
#define pte_offset(pt, va)    (pte_deref(pt) + (pt_index(va) << 3))

#define pml4e_none(pml4e) (!((pml4e) & PML4E_PRESENT))
#define pdpe_none(pdpe)   (!((pdpe) & PDPE_PRESENT))
#define pde_none(pde)     (!((pde) & PDE_PRESENT))
#define pte_none(pte)     (!((pte) & PTE_PRESENT))

#define pml4e_val(pml4e) ((pml4e) & 0xfffUL)
#define pdpe_val(pdpe)   ((pdpe) & 0xfffUL)
#define pde_val(pde)     ((pde) & 0xfffUL)
#define pte_val(pte)     ((pte) & 0xfffUL)

#define pml4e_bad(pml4e) (!(pml4e_val(pml4e) & PML4E_BAD))
#define pdpe_bad(pdpe)   (!(pdpe_val(pdpe) & PDPE_BAD))
#define pde_bad(pde)     (!(pde_val(pde) & PDE_BAD))
#define pte_bad(pte)     (!(pte_val(pte) & PTE_BAD))

#define pml4e_present(pml4e) ((pml4e) & 0x1)
#define pdpe_present(pdpe)   ((pdpe) & 0x1)
#define pde_present(pde)     ((pde) & 0x1)
#define pte_present(pte)     ((pte) & 0x1)
#endif

#define bitset(x, n) ((x) | (1UL << (n)))
#define bitclr(x, n) ((x) & ~(1UL << (n)))

#define padding(level) ((level)*4 + 4)

#define PGTABLE_MMAP_BASE 0x200000000UL
#define PGTABLE_MMAP_SIZE BIT(36)
#define PGTABLE_MMAP_END  (PGTABLE_MMAP_BASE + PGTABLE_MMAP_SIZE)

typedef uint64_t PhysAddr;
typedef uint64_t VirtAddr;
typedef uint64_t PhysFrame;

static inline bool is_aligned(PhysAddr addr, size_t alignment) {
    return (addr % alignment) == 0;
}

int pgtable_init(uint64_t **pgd, uint64_t cr3, int fd);
int pgtable_free(uint64_t *pgd);
int pgtable_selftest(uint64_t *pgd, uint64_t va);

int pgtable_mmap(uint64_t *pgd, uint64_t va, size_t len, int perm);
int pgtable_mprotect(uint64_t *pgd, uint64_t va, size_t len, int perm);
int pgtable_unmap(uint64_t *pgd, uint64_t va, size_t len, int level);

int lookup_address_in_pgd(uint64_t *pgd, uint64_t va, int *level, pte_t **ptep);
int lookup_address(uint64_t va, uint64_t *level, pte_t **ptep);

uint64_t pgtable_pa_to_va(uint64_t pa);
uint64_t pgtable_va_to_pa(uint64_t va);

// Memory allocation in the guest process
void *vmpl_alloc(size_t size);
void vmpl_free(void *addr);

#endif