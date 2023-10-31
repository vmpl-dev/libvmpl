#ifndef _LIBVMPL_MM_H
#define _LIBVMPL_MM_H

#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

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

#ifdef NEW
struct pte_t {
    uint64_t present:1;
    uint64_t writable:1;
    uint64_t user:1;
    uint64_t write_through:1;
    uint64_t cache_disable:1;
    uint64_t accessed:1;
    uint64_t dirty:1;
    uint64_t pat:1;
    uint64_t global:1;
    uint64_t available:3;
    uint64_t page_frame:40;
    uint64_t reserved2:11;
    uint64_t no_execute:1;
};
#endif

#define PAGE_SIZE 4096
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_DOWN(x) ((x) & ~(PAGE_SIZE - 1))

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

#define p4d_none(p4d) (!(p4d & P4D_PRESENT))
#define pud_none(pud) (!(pud & PUD_PRESENT))
#define pmd_none(pmd) (!(pmd & PMD_PRESENT))
#define pte_none(pte) (!(pte & PTE_PRESENT))

#define p4d_bad(p4d) (p4d & P4D_BAD)
#define pud_bad(pud) (pud & PUD_BAD)
#define pmd_bad(pmd) (pmd & PMD_BAD)
#define pte_bad(pte) (pte & PTE_BAD)

#define p4d_present(p4d) ((p4d) & 0x1)
#define pud_present(pud) ((pud) & 0x1)
#define pmd_present(pmd) ((pmd) & 0x1)
#define pte_present(pte) ((pte) & 0x1)
#else
#define PML4E_PRESENT (1UL << 0)
#define PDPE_PRESENT  (1UL << 0)
#define PDE_PRESENT   (1UL << 0)
#define PTE_PRESENT   (1UL << 0)

#define PML4E_BAD (1UL << 1)
#define PDPE_BAD  (1UL << 1)
#define PDE_BAD   (1UL << 1)
#define PTE_BAD   (1UL << 1)

#define pml4_index(va) (((unsigned long)(va) >> 39) & 0x1ff)
#define pdp_index(va)  (((unsigned long)(va) >> 30) & 0x1ff)
#define pd_index(va)   (((unsigned long)(va) >> 21) & 0x1ff)
#define pt_index(va)   (((unsigned long)(va) >> 12) & 0x1ff)

#define pml4_offset(pml4, va) ((pml4) + pml4_index(va))
#define pdp_offset(pdp, va)   ((pdp) + pdp_index(va))
#define pd_offset(pd, va)     ((pd) + pd_index(va))
#define pte_offset(pt, va)    ((pt) + pt_index(va))

#define pml4e_none(pml4e) (!(pml4e & PML4E_PRESENT))
#define pdpe_none(pdpe)   (!(pdpe & PDPE_PRESENT))
#define pde_none(pde)     (!(pde & PDE_PRESENT))
#define pte_none(pte)     (!(pte & PTE_PRESENT))

#define pml4e_bad(pml4e) (pml4e & PML4E_BAD)
#define pdpe_bad(pdpe)   (pdpe & PDPE_BAD)
#define pde_bad(pde)     (pde & PDE_BAD)
#define pte_bad(pte)     (pte & PTE_BAD)

#define pml4e_present(pml4e) ((pml4e) & 0x1)
#define pdpe_present(pdpe)   ((pdpe) & 0x1)
#define pde_present(pde)     ((pde) & 0x1)
#define pte_present(pte)     ((pte) & 0x1)
#endif

#define pte_addr(pte) (pte & 0x7fffffffff000UL)

#define pfn2page(pfn) (pfn << 12)
#define page2pfn(page) (page >> 12)

#define bitclr(x, n) ((x) & ~(1UL << (n)))

#define padding(level) ((level)*4 + 4)

typedef uint64_t PhysAddr;
typedef uint64_t VirtAddr;
typedef uint64_t PhysFrame;

static inline bool is_aligned(PhysAddr addr, size_t alignment) {
    return (addr % alignment) == 0;
}

int pgtable_init(uint64_t **pgd, uint64_t cr3, int fd);
int pgtable_free(uint64_t *pgd);

int pgtable_mmap(uint64_t *pgd, uint64_t va, size_t len, int perm);
int pgtable_mprotect(uint64_t *pgd, uint64_t va, size_t len, int perm);
int pgtable_unmap(uint64_t *pgd, uint64_t va, size_t len, int level);

int lookup_address_in_pgd(uint64_t *pgd, uint64_t va, int level, uint64_t *pa);
int lookup_address(uint64_t va, uint64_t level, uint64_t *pa);

uint64_t pgtable_pa_to_va(uint64_t pa);
uint64_t pgtable_va_to_pa(uint64_t va);

#endif