#ifndef _LIBVMPL_MM_H
#define _LIBVMPL_MM_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "config.h"
#include "sys.h"

#define GENMASK_ULL(h, l) \
    (((~0ULL) << (l)) & (~0ULL >> (64 - 1 - (h))))
#define BIT_64(nr) (1UL << (nr))

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
#define PAGE_OFFSET(addr) ((addr) & (PAGE_SIZE - 1))
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) PAGE_ALIGN(x)
#define PAGE_ALIGN_DOWN(x) ((x) & ~(PAGE_SIZE - 1))
#define PAGE_MASK(x) ((x) & (PAGE_SIZE - 1))
#define PTE_PKEY_SHIFT 59

#ifdef CONFIG_PGTABLE_LA57
#define P4D_PRESENT (1UL << 0)
#define PUD_PRESENT (1UL << 0)
#define PMD_PRESENT (1UL << 0)
#define PTE_PRESENT (1UL << 0)

#define P4D_BAD (1UL << 1)
#define PUD_BAD (1UL << 1)
#define PMD_BAD (1UL << 1)
#define PTE_BAD (1UL << 1)

#define pgd_index(va) PDX(4, va)
#define p4d_index(va) PDX(3, va)
#define pud_index(va) PDX(2, va)
#define pmd_index(va) PDX(1, va)
#define pte_index(va) PDX(0, va)

#define pgd_offset(pgd, va) ((pgd) + pgd_index(va))
#define p4d_offset(pgd, va) ((pgd) + p4d_index(va))
#define pud_offset(p4d, va) ((p4d) + pud_index(va))
#define pmd_offset(pud, va) ((pud) + pmd_index(va))
#define pte_offset(pmd, va) ((pmd) + pte_index(va))

#define pgd_none(pgd) (!(pgd & PGD_PRESENT))
#define p4d_none(p4d) (!(p4d & P4D_PRESENT))
#define pud_none(pud) (!(pud & PUD_PRESENT))
#define pmd_none(pmd) (!(pmd & PMD_PRESENT))
#define pte_none(pte) (!(pte & PTE_PRESENT))

#define pgd_bad(pgd) (pgd & P4D_BAD)
#define p4d_bad(p4d) (p4d & P4D_BAD)
#define pud_bad(pud) (pud & PUD_BAD)
#define pmd_bad(pmd) (pmd & PMD_BAD)
#define pte_bad(pte) (pte & PTE_BAD)

#define pgd_present(pgd) ((pgd) & PGD_PRESENT)
#define p4d_present(p4d) ((p4d) & P4D_PRESENT)
#define pud_present(pud) ((pud) & PUD_PRESENT)
#define pmd_present(pmd) ((pmd) & PMD_PRESENT)
#define pte_present(pte) ((pte) & PTE_PRESENT)
#else
#define PTE_P       BIT_64(0)    /* Present */
#define PTE_W       BIT_64(1)    /* Writable */
#define PTE_U       BIT_64(2)    /* User-accessible */
#define PTE_PWT     BIT_64(3)    /* Write-through */
#define PTE_PCD     BIT_64(4)    /* Cache disabled */
#define PTE_A       BIT_64(5)    /* Accessed */
#define PTE_D       BIT_64(6)    /* Dirty */
#define PTE_PS      BIT_64(7)    /* Page-size */
#define PTE_PAT     BIT_64(7)    /* PAT */
#define PTE_G       BIT_64(8)    /* Global */
#define PTE_AVAIL   GENMASK_ULL(11, 9) /* Available for software use */
#define PTE_PAT_PS  BIT_64(12) /* Page size */
#define PTE_C       BIT_64(51)   /* Encrypted page */
#define PTE_AVAIL2  GENMASK_ULL(63, 52) /* Available for software use */
#define PTE_NX      BIT_64(63)   /* No execute: only if NX feature present */
#define ADDR_MASK   GENMASK_ULL(50, 12) /* Address mask */

#define PAGE_PRESENT  PTE_P
#define PAGE_RW       PTE_W
#define PAGE_ACCESSED PTE_A
#define PAGE_DIRTY    PTE_D
#define PAGE_GLOBAL   PTE_G
#define PAGE_KERNEL (PAGE_PRESENT | PAGE_RW | PAGE_ACCESSED | PAGE_DIRTY | PAGE_GLOBAL)
#define PAGE_USER   (PAGE_PRESENT | PAGE_RW | PAGE_ACCESSED | PAGE_DIRTY)

#define PML4E_BAD (1UL << 1)
#define PDPE_BAD  (1UL << 1)
#define PDE_BAD   (1UL << 1)
#define PTE_BAD   (1UL << 1)

#define page_address(page) ((page) << 12)
#define pte_addr(pte) ((pte) & ADDR_MASK)
#define pfn2page(pfn) ((pfn) << 12)
#define page2pfn(page) ((page) >> 12)

#define pml4_index(va) PDX(3, va)
#define pdp_index(va)  PDX(2, va)
#define pd_index(va)   PDX(1, va)
#define pt_index(va)   PDX(0, va)

#define pml4_deref(pml4)   __va(pte_addr(*pml4))
#define pdpe_deref(pdpe)   __va(pte_addr(*pdpe))
#define pde_deref(pde)     __va(pte_addr(*pde))
#define pte_deref(pte)     __va(pte_addr(*pte))

#define pml4_offset(pml4, va) ((pml4) + (pml4_index(va) << 3))
#define pdp_offset(pdp, va)   (pdpe_deref(pdp) + (pdp_index(va) << 3))
#define pd_offset(pd, va)     (pde_deref(pd) + (pd_index(va) << 3))
#define pte_offset(pt, va)    (pte_deref(pt) + (pt_index(va) << 3))

#define pml4e_none(pml4e) (!((pml4e) & PTE_P))
#define pdpe_none(pdpe)   (!((pdpe) & PTE_P))
#define pde_none(pde)     (!((pde) & PTE_P))
#define pte_none(pte)     (!((pte) & PTE_P))

#define pml4e_val(pml4e) ((pml4e) & 0xfffUL)
#define pdpe_val(pdpe)   ((pdpe) & 0xfffUL)
#define pde_val(pde)     ((pde) & 0xfffUL)
#define pte_val(pte)     ((pte) & 0xfffUL)

#define pml4e_bad(pml4e) (!(pml4e_val(pml4e) & PML4E_BAD))
#define pdpe_bad(pdpe)   (!(pdpe_val(pdpe) & PDPE_BAD))
#define pde_bad(pde)     (!(pde_val(pde) & PDE_BAD))
#define pte_bad(pte)     (!(pte_val(pte) & PTE_BAD))

#define pml4e_present(pml4e) ((pml4e) & PTE_P)
#define pdpe_present(pdpe)   ((pdpe) & PTE_P)
#define pde_present(pde)     ((pde) & PTE_P)
#define pte_present(pte)     ((pte) & PTE_P)

#define pml4e_write(pml4e) ((pml4e) & PTE_W)
#define pdpe_write(pdpe)   ((pdpe) & PTE_W)
#define pde_write(pde)     ((pde) & PTE_W)
#define pte_write(pte)     ((pte) & PTE_W)

#define pte_big(pte)       ((pte) & 0x80)
#define pte_vmpl(pte)      ((pte) & PTE_VMPL)
#endif

#define pte_flags(pte) ((pte) & 0xfffUL)
#define pte_clear(mm, addr, ptep) set_pte(ptep, 0)
#define pte_page(pte) ((pte) >> 12)
#define pfn_pte(pfn, prot) ((pfn) | (prot))
#define set_pte(ptep, pte) (*(ptep) = (pte))
#define bitset(x, n) ((x) | (1UL << (n)))
#define bitclr(x, n) ((x) & ~(1UL << (n)))

#define padding(level) ((level)*4 + 4)

#define PGTABLE_MMAP_BASE 0x200000000UL /* 8GB */
#define PGTABLE_MMAP_SIZE 0x180000000UL /* 6GB */
#define PGTABLE_MMAP_END  (PGTABLE_MMAP_BASE + PGTABLE_MMAP_SIZE)

#define PDADDR(n, i)	(((unsigned long) (i)) << PDSHIFT(n))
#define PTE_DEF_FLAGS	(PTE_P | PTE_W | PTE_U | PTE_C)
#define PTE_VMPL_FLAGS  (PTE_W | PTE_U | PTE_C| PTE_VMPL)
#define LGPGSIZE	(1 << (PGSHIFT + NPTBITS))

typedef uint64_t PhysAddr;
typedef uint64_t VirtAddr;
typedef uint64_t PhysFrame;

static inline bool is_aligned(PhysAddr addr, size_t alignment) {
    return (addr % alignment) == 0;
}

extern int dune_fd;
extern pte_t *pgroot;
int pgtable_init(pte_t **pgd, int fd);
int pgtable_exit(pte_t *pgd);
int pgtable_free(pte_t *pgd);
void pgtable_stats(pte_t *pgd);
#ifdef CONFIG_VMPL_TEST
void pgtable_test(pte_t *pgd, uint64_t va);
#else
static inline void pgtable_test(pte_t *pgd, uint64_t va) {}
#endif
void pgtable_load_cr3(uint64_t cr3);
pte_t *pgtable_do_mapping(uint64_t phys);
int pgtable_lookup(pte_t *root, void *va, int create, pte_t **pte_out);
int pgtable_create(pte_t *root, void *va, pte_t **pte_out);
int pgtable_update_leaf_pte(pte_t *pgd, uint64_t va, uint64_t pa);

int lookup_address_in_pgd(pte_t *pgd, uint64_t va, int *level, pte_t **ptep);
int lookup_address(uint64_t va, int *level, pte_t **ptep);

uint64_t pgtable_pa_to_va(uint64_t pa);
uint64_t pgtable_va_to_pa(uint64_t va);

#endif