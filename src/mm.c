#define _GNU_SOURCE
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>

#include "mm.h"
#include "sev.h"
#include "log.h"
#include "bitmap.h"
#include "pgtable.h"

#define __va(x) ((void *)((unsigned long)(x) + PGTABLE_MMAP_BASE))
#define __pa(x) ((unsigned long)(x) - PGTABLE_MMAP_BASE)
#define phys_to_virt(x) __va(x)
#define virt_to_phys(x) __pa(x)

#define padding(level) ((level)*4 + 4)
static char *pt_names[] = { "PML4", "PDP", "PD", "PT", "Page" };
static uint64_t *this_pgd;
static void *free_pages;

/**
 * @brief  Setup page table self-mapping
 * @note   
 * @param  paddr: Physical address of the page table
 * @param  level: Level of the page table
 * @param  fd: File descriptor of the vmpl-dev
 * @retval 
 */
static int __pgtable_init(uint64_t paddr, int level, int fd)
{
	size_t max_i;
	uint64_t *vaddr;

    if (level == 4)
        return 0;

    bitclr(paddr, 63);
    bitclr(paddr, 51);

    vaddr = mmap((void *)(PGTABLE_MMAP_BASE + paddr), PAGE_SIZE,
				 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (vaddr == MAP_FAILED) {
        perror("dune: failed to map pgtable");
        goto failed;
    }

    log_trace("%*s%s [%p - %09lx]", padding(level), "", pt_names[level], vaddr, paddr);
    max_i = (level != 0) ? 512 : 256;
    for (int i = 0; i < max_i; i++) {
        if (vaddr[i] & 0x1) {
            log_trace("%*s%s Entry[%d]: %016lx", padding(level), "", pt_names[level], i, vaddr[i]);
            __pgtable_init(pte_addr(vaddr[i]), level + 1, fd);
        }
    }

	return 0;
failed:
    return -ENOMEM;
}

static int __pgtable_init_free_pages(int fd)
{
    void *addr;
    addr = mmap((void *)PGTABLE_MMAP_BASE, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("dune: failed to map pgtable");
        goto failed;
    }

    return 0;
failed:
    return -ENOMEM;
}

int pgtable_init(uint64_t **pgd, uint64_t cr3, int fd)
{
	int rc;
	log_debug("pgtable init");

	rc = __pgtable_init(cr3, 0, fd);
    if (rc) {
        log_err("pgtable init failed");
        return rc;
    }

    *pgd = (uint64_t *)(PGTABLE_MMAP_BASE + cr3);
    this_pgd = *pgd;
    return 0;
}

int pgtable_free(uint64_t *pgd)
{
    log_debug("pgtable free");
    // TODO: free should be implemented in pgtable_free
    return 0;
}

int pgtable_selftest(uint64_t *pgd, uint64_t va)
{
    int rc;
    pte_t *ptep;
    int level;

    log_debug("pgtable selftest");

    rc = lookup_address_in_pgd(pgd, va, &level, &ptep);
    if (rc) {
        log_err("lookup address in pgd failed");
        return rc;
    }

    log_debug("level: %d, pa: %lx", level, pte_addr(*ptep));

    rc = lookup_address(va, &level, &ptep);
    if (rc) {
        log_err("lookup address failed");
        return rc;
    }

    log_debug("level: %d, pa: %lx", level, pte_addr(*ptep));

    return 0;
}

int pgtable_mmap(uint64_t *pgd, uint64_t va, size_t len, int perm)
{
    log_debug("pgtable mmap");
    // TODO: mmap should be implemented in pgtable_mmap
    return 0;
}

int pgtable_mprotect(uint64_t *pgd, uint64_t va, size_t len, int perm)
{
    log_debug("pgtable mprotect");
    // TODO: mprotect should be implemented in pgtable_mprotect
    return 0;
}

int pgtable_unmap(uint64_t *pgd, uint64_t va, size_t len, int level)
{
    log_debug("pgtable unmap");
    // TODO: unmap should be implemented in pgtable_unmap
    return 0;
}

int lookup_address_in_pgd(uint64_t *pgd, uint64_t va, int *level, pte_t **ptep)
{
    log_debug("lookup address in pgd");
    log_trace("pgd: %p, va: %lx", pgd, va);

    pml4e_t *pml4e = pml4_offset(pgd, va);
    log_trace("pml4e: %p, *pml4e: %lx", pml4e, *pml4e);
    if (pml4e_none(*pml4e) || pml4e_bad(*pml4e)) {
        log_err("pml4e is none");
        return -EINVAL;
    }

    if (level)
        *level = 4;

    pdpe_t *pdpe = pdp_offset(pml4e, va);
    log_trace("pdpe: %p, *pdpe: %lx", pdpe, *pdpe);
    if (pdpe_none(*pdpe) || pdpe_bad(*pdpe)) {
        log_err("pdpe is none");
        return -EINVAL;
    }

    if (level)
        *level = 3;

    pde_t *pde = pd_offset(pdpe, va);
    log_trace("pde: %p, *pde: %lx", pde, *pde);
    if (pde_none(*pde) || pde_bad(*pde)) {
        log_err("pde is none");
        return -EINVAL;
    }

    if (level)
        *level = 2;

    pte_t *pte = pte_offset(pde, va);
    log_trace("pte: %p, *pte: %lx", pte, *pte);
    if (pte_none(*pte) || !pte_present(*pte)) {
        log_err("pte is none");
        return -EINVAL;
    }

    if (ptep)
        *ptep = pte;

    if (level)
        *level = 1;

    return 0;
}

int lookup_address(uint64_t va, uint64_t *level, pte_t **ptep)
{
    log_debug("lookup address");
    if (this_pgd == NULL) {
        log_err("pgd is NULL");
        return -EINVAL;
    }

    return lookup_address_in_pgd(this_pgd, va, level, ptep);
}

uint64_t pgtable_pa_to_va(uint64_t pa)
{
    return phys_to_virt(pa);
}

uint64_t pgtable_va_to_pa(uint64_t va)
{
    uint64_t pa;
    int level;

    if ((va > PGTABLE_MMAP_BASE) && (va < PGTABLE_MMAP_BASE + PAGE_SIZE)) {
        return virt_to_phys(va);
    } else {
        int rc = lookup_address(va, &level, &pa);
        if (rc) {
            log_err("lookup address failed");
            return 0;
        }
    }

    return pa;
}