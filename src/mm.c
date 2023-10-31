#define _GNU_SOURCE
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>

#include "mm.h"
#include "sev.h"
#include "log.h"
#include "pgtable.h"

#define __va(x) ((void *)((unsigned long)(x) + PGTABLE_MMAP_BASE))
#define __pa(x) ((unsigned long)(x) - PGTABLE_MMAP_BASE)
#define phys_to_virt(x) __va(x)
#define virt_to_phys(x) __pa(x)

#define padding(level) ((level)*4 + 4)
static char *pt_names[] = { "PML4", "PDP", "PD", "PT", "Page" };
static void *pgd;

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
	uint64_t *vaddr;

    if (level == 4)
        return 0;

    bitclr(paddr, 63);
    bitclr(paddr, 51);

    vaddr = mmap((void *)(PGTABLE_MMAP_BASE + paddr), PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (vaddr == MAP_FAILED) {
        perror("dune: failed to map pgtable");
        goto failed;
    }

	log_debug("%*s%s [%p - %09lx]", padding(level), "", pt_names[level], vaddr, paddr);
    for (int i = 0; i < 512; i++) {
        if (vaddr[i] & 0x1) {
            log_trace("%*s%s Entry[%d]: %016lx", padding(level), "", pt_names[level], i, vaddr[i]);
            __pgtable_init(pte_addr(vaddr[i]), level + 1, fd);
        }
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
    return 0;
}

int pgtable_free(uint64_t *pgd)
{
    log_debug("pgtable free");
    // TODO: free should be implemented in pgtable_free
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

int lookup_address_in_pgd(uint64_t *pgd, uint64_t va, int level, uint64_t *pa)
{
    log_debug("lookup address in pgd");
    // TODO: lookup should be implemented in lookup_address_in_pgd
    pml4e_t *pml4e = pml4_offset(pgd, va);
    if (pml4e_none(*pml4e) || pml4e_bad(*pml4e)) {
        log_err("pml4e is none");
        return -EINVAL;
    }

    pdpe_t *pdpe = pdp_offset(pml4e, va);
    if (pdpe_none(*pdpe) || pdpe_bad(*pdpe)) {
        log_err("pdpe is none");
        return -EINVAL;
    }

    pde_t *pde = pd_offset(pdpe, va);
    if (pde_none(*pde) || pde_bad(*pde)) {
        log_err("pde is none");
        return -EINVAL;
    }

    pte_t *pte = pte_offset(pde, va);
    if (pte_none(*pte) || !pte_present(*pte)) {
        log_err("pte is none");
        return -EINVAL;
    }

    *pa = pte_addr(*pte);

    return 0;
}

int lookup_address(uint64_t va, uint64_t level, uint64_t *pa)
{
    log_debug("lookup address");
    if (pgd == NULL) {
        log_err("pgd is NULL");
        return -EINVAL;
    }

    return lookup_address_in_pgd(pgd, va, 4, pa);
}

uint64_t pgtable_pa_to_va(uint64_t pa)
{
    return phys_to_virt(pa);
}

uint64_t pgtable_va_to_pa(uint64_t va)
{
    return virt_to_phys(va);
}