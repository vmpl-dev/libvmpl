#ifndef _LIBVMPL_MM_H
#define _LIBVMPL_MM_H

#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "sys.h"

typedef uint64_t pgd_t;
typedef uint64_t p4d_t;
typedef uint64_t pmd_t;
typedef uint64_t pud_t;
typedef uint64_t pte_t;

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

#define pte_present(pte) ((pte) & 0x1)
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

uint64_t pgtable_pa_to_va(uint64_t pa);
uint64_t pgtable_va_to_pa(uint64_t va);

#endif