#ifndef _LIBVMPL_MM_H
#define _LIBVMPL_MM_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "config.h"

#define GENMASK_ULL(h, l) \
    (((~0ULL) << (l)) & (~0ULL >> (64 - 1 - (h))))
#define BIT_64(nr) (1UL << (nr))

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_OFFSET(addr) ((addr) & (PAGE_SIZE - 1))
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) PAGE_ALIGN(x)
#define PAGE_ALIGN_DOWN(x) ((x) & ~(PAGE_SIZE - 1))
#define PAGE_MASK(x) ((x) & (PAGE_SIZE - 1))
#define PTE_PKEY_SHIFT 59

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
#define PTE_COW     BIT_64(9)    /* Copy-on-write */
#define PTE_VMPL    BIT_64(10)   /* VMPL page */
#define PTE_AVAIL   GENMASK_ULL(11, 9) /* Available for software use */
#define PTE_PAT_PS  BIT_64(12) /* Page size */
#define PTE_C       BIT_64(51)   /* Encrypted page */
#define PTE_AVAIL2  GENMASK_ULL(63, 52) /* Available for software use */
#define PTE_NX      BIT_64(63)   /* No execute: only if NX feature present */
#define PTE_MPK     GENMASK_ULL(62, 59) /* Memory Protection Keys (MPK) Bit */
#define ADDR_MASK   GENMASK_ULL(50, 12) /* Address mask */

#define PAGE_PRESENT  PTE_P
#define PAGE_RW       PTE_W
#define PAGE_ACCESSED PTE_A
#define PAGE_DIRTY    PTE_D
#define PAGE_GLOBAL   PTE_G
#define PAGE_KERNEL (PAGE_PRESENT | PAGE_RW | PAGE_ACCESSED | PAGE_DIRTY | PAGE_GLOBAL)
#define PAGE_USER   (PAGE_PRESENT | PAGE_RW | PAGE_ACCESSED | PAGE_DIRTY)

#define PTE_BAD   (1UL << 1)

#define page_address(page) ((page) << 12)

#define pfn2page(pfn) ((pfn) << 12)
#define page2pfn(page) ((page) >> 12)

typedef uint64_t pgd_t;
typedef uint64_t p4d_t;
typedef uint64_t pmd_t;
typedef uint64_t pud_t;
typedef uint64_t pte_t;

#define PTE_PRESENT (1UL << 0)
#define PTE_BAD (1UL << 1)

#define pgd_index(va) PDX(4, va)
#define p4d_index(va) PDX(3, va)
#define pud_index(va) PDX(2, va)
#define pmd_index(va) PDX(1, va)
#define pte_index(va) PDX(0, va)

#define pte_deref(pte)   __va(pte_addr(*pte))

#ifdef CONFIG_PGTABLE_LA57
#define pgd_offset(pgd, va) ((pgd) + (pgd_index(va) << 3))
#define p4d_offset(p4d, va) (pte_deref(pgd) + (p4d_index(va) << 3))
#else
#define p4d_offset(p4d, va) ((p4d) + (p4d_index(va) << 3))
#endif
#define pud_offset(pud, va) (pte_deref(p4d) + (pud_index(va) << 3))
#define pmd_offset(pud, va) (pte_deref(pud) + (pmd_index(va) << 3))
#define pte_offset(pte, va) (pte_deref(pte) + (pte_index(va) << 3))

#define pte_none(pte)       (!((pte) & PTE_P))
#define pte_val(pte)        ((pte) & 0xfffUL)
#define pte_bad(pte)        (!(pte_val(pte) & PTE_BAD))
#define pte_user(pte)       ((pte) & PTE_U)
#define pte_present(pte)    ((pte) & PTE_P)
#define pte_write(pte)      ((pte) & PTE_W)
#define pte_big(pte)        ((pte) & PTE_PS)
#define pte_vmpl(pte)       ((pte) & PTE_VMPL)

#define pte_addr(pte) ((pte) & ADDR_MASK)
#define pte_flags(pte) ((pte) & ~ADDR_MASK)
#define pte_clear(mm, addr, ptep) set_pte(ptep, 0)
#define pte_page(pte) ((pte) >> 12)
#define pfn_pte(pfn, prot) ((pfn) | (prot))
#define set_pte(ptep, pte) (*(ptep) = (pte))

#define bitset(x, n) ((x) | (1UL << (n)))
#define bitclr(x, n) ((x) & ~(1UL << (n)))

#define padding(level) ((level)*4 + 4)

#define PDADDR(n, i)	(((unsigned long) (i)) << PDSHIFT(n))
#define PT_DEF_FLAGS   (PTE_P | PTE_W | PTE_U | PTE_C)
#define PTE_DEF_FLAGS	(PTE_P | PTE_W | PTE_U | PTE_C)
#define PTE_VMPL_FLAGS  (PTE_W | PTE_U | PTE_C| PTE_VMPL)
#define LGPGSIZE	(1 << (PGSHIFT + NPTBITS))

/**
 * 页表级别枚举
 * 从低到高依次为: PTE -> PMD -> PUD -> P4D -> PGD
 */
enum page_level {
    PT_LEVEL_PTE = 0, // Page Table Entry (4KB页)
    PT_LEVEL_PMD = 1,  // Page Middle Directory (2MB页)
    PT_LEVEL_PUD = 2,  // Page Upper Directory (1GB页)
    PT_LEVEL_P4D = 3,  // Page 4th Directory
#ifdef CONFIG_PGTABLE_LA57
    PT_LEVEL_PGD = 4,  // Page Global Directory
#else
    PT_LEVEL_PGD = 3,  // Page Global Directory
#endif
};

/**
 * @brief 页表创建类型枚举
 * 与dune.h中定义保持一致
 */
enum create_mode {
    CREATE_NONE = 0,
    CREATE_NORMAL = 1,
    CREATE_BIG = 2,
    CREATE_BIG_1GB = 3,
};

/**
 * @brief Check if the page is a COW page
 * @note Check if the page is a COW page by checking if the page table entry has
 * the COW bit set and the read/write bit cleared.
 * @param pte page table entry
 * @return true if the page is a COW page, false otherwise
 */
static inline bool is_cow_page(pte_t pte)
{
	return (pte & (PTE_COW | PTE_W)) == PTE_COW;
}

/**
 * @brief Mark the page as a COW page
 * @note Mark the page as a COW page and clear the read/write bit.
 * @param ptep page table entry
 */
static inline void set_cow_page(pte_t *ptep)
{
	*ptep |= PTE_COW;
	*ptep &= ~PTE_W;
}

/**
 * @brief Clear the COW bit from the page table entry
 * @note Clear the COW bit from the page table entry and set the read/write bit.
 * @param ptep page table entry
 */
static inline void clear_cow_page(pte_t *ptep)
{
    *ptep &= ~PTE_COW;
    *ptep |= PTE_W;
}

typedef uint64_t PhysAddr;
typedef uint64_t VirtAddr;
typedef uint64_t PhysFrame;

static inline bool is_aligned(PhysAddr addr, size_t alignment) {
    return (addr % alignment) == 0;
}

extern pte_t *pgroot;
int pgtable_init();
int pgtable_exit(pte_t *pgd);
int pgtable_free(pte_t *pgd);
void pgtable_stats(pte_t *pgd);
#ifdef CONFIG_VMPL_TEST
void pgtable_test(pte_t *pgd, uint64_t va);
#else
static inline void pgtable_test(pte_t *pgd, uint64_t va) {}
#endif
pte_t *pgtable_do_mapping(uint64_t phys);
int pgtable_lookup(pte_t *root, void *va, int create, pte_t **pte_out);
int pgtable_create(pte_t *root, void *va, pte_t **pte_out);
int pgtable_update_leaf_pte(pte_t *pgd, uint64_t va, uint64_t pa);

int lookup_address_in_pgd(pte_t *root, uint64_t va, int *level, pte_t **ptep);
int lookup_address(uint64_t va, int *level, pte_t **ptep);

uint64_t pgtable_pa_to_va(uint64_t pa);
uint64_t pgtable_va_to_pa(uint64_t va);

#endif