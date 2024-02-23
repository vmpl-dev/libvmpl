/**
 * 深度优先遍历页表，将进程物理内存页的vmpl属性标记为1，增加引用计数，
 * 这样就可以自行回收物理页了。对于满足vmpl=1，refcount=1的物理页，都可以纳入到空闲页链表中。
 * 而对于map过的物理页，vmpl=1, refcount=1，但是不在空闲页链表中，这些物理页是不能回收的。
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include "vmpl-dev.h"
#include "vmpl-ioctl.h"
#include "sev.h"
#include "log.h"
#include "mmu.h"
#include "page.h"
#include "pgtable.h"

#define MEMORY_POOL_START   PGTABLE_MMAP_BASE
#define MEMORY_POOL_END     PGTABLE_MMAP_END

#define __va(x) ((void *)((unsigned long)(x) + PGTABLE_MMAP_BASE))
#define __pa(x) ((unsigned long)(x) - PGTABLE_MMAP_BASE)
#define phys_to_virt(x) __va(x)
#define virt_to_phys(x) __pa(x)

#define padding(level) ((level)*4 + 4)
static char *pt_names[] = { "P4D", "PUD", "PMD", "PTE", "Page" };
pte_t *pgroot;

static inline virtaddr_t pgtable_alloc(void)
{
	struct page *pg;
	physaddr_t pa;
	virtaddr_t va;

	pg = dune_page_alloc(dune_fd);
	if (!pg)
		return NULL;
	
	pa = dune_page2pa(pg);
	va = pgtable_pa_to_va(pa);
    assert(pa >= PAGEBASE);
    assert(va >= PGTABLE_MMAP_BASE);
    assert(va < PGTABLE_MMAP_END);
    assert(pa == (va - PGTABLE_MMAP_BASE));
    assert(pg == vmpl_pa2page(pa));
    assert(pg->flags == 1);
    memset(va, 0, PAGE_SIZE);
	log_debug("pg = 0x%lx, pa = 0x%lx, va = 0x%lx, ref = %d", pg, pa, va, pg->ref);
	return va;
}

/**
 * @brief  Setup page table self-mapping
 * @note   The page table is mapped to the virtual address space of the process, such that
 * the page table can be accessed by the process. The physical page are marked as vmpl page,
 * and the reference count is set to 0, such that the page can be reclaimed by the process.
 * The pages used to mappt the page table are not marked as vmpl page, and the reference count
 * is set to 0, such that the pages are not reclaimed by the process.
 * @param  paddr: Physical address of the page table
 * @param  level: Level of the page table
 * @param  fd: File descriptor of the vmpl-dev
 * @retval 
 */
static int __pgtable_init(uint64_t paddr, int level, int fd, int *pgtable_count, int *page_count)
{
    size_t max_i;
    uint64_t *vaddr;
    struct page *pg;

    // Mark page as vmpl page
    vmpl_page_mark_addr(paddr);

    // If this is a leaf page table
    if (level == 4) {
        (*page_count)++;
        return 0;
    }

    // Map page table to virtual address space
    vaddr = do_mapping(fd, paddr, PAGE_SIZE);
    if (vaddr == MAP_FAILED) {
        perror("dune: failed to map pgtable");
        goto failed;
    }

    // Traverse page table
    log_trace("%*s%s [%p - %09lx]", padding(level), "", pt_names[level], vaddr, paddr);
    max_i = (level != 0) ? 512 : 256;
    for (int i = 0; i < max_i; i++) {
        if (vaddr[i] & 0x1) {
            log_trace("%*s%s Entry[%d]: %016lx", padding(level), "", pt_names[level], i, vaddr[i]);
            __pgtable_init(pte_addr(vaddr[i]), level + 1, fd, pgtable_count, page_count);
        }
    }

    // Increment page count
    (*pgtable_count)++;

    return 0;
failed:
    return -ENOMEM;
}

int pgtable_init(pte_t **pgd, int fd)
{
	int rc;
    uint64_t cr3;
	size_t pgtable_count = 0;
    size_t page_count = 0;
	log_debug("pgtable init");

	// Get CR3
    rc = vmpl_ioctl_get_cr3(fd, &cr3);
    if (rc) {
        log_err("get cr3 failed");
        return rc;
    }

    log_debug("dune: CR3 at 0x%lx", cr3);

    // Initialize page table
	rc = __pgtable_init(cr3, 0, fd, &pgtable_count, &page_count);
    if (rc) {
        log_err("pgtable init failed");
        return rc;
    }

    log_debug("dune: %lu page tables, %lu pages", pgtable_count, page_count);
    *pgd = pgtable_pa_to_va(cr3);
    pgroot = *pgd;

    return 0;
}

int pgtable_exit(pte_t *pgd)
{
    log_debug("pgtable exit");

    return 0;
}

int pgtable_free(pte_t *pgd)
{
    log_debug("pgtable free");
    return 0;
}

void pgtable_stats(pte_t *pgd)
{
    printf("Page Table Stats:\n");
}

#ifdef CONFIG_VMPL_TEST
/**
 * @brief  Test the page table.
 * @param pgd: The page table of the process.
 * @param va: The virtual address of the page.
 * @retval None
 */
void pgtable_test(pte_t *pgd, uint64_t va)
{
    int rc;
    pte_t *ptep;
    int level;

    log_info("Page Table Test");
    rc = lookup_address_in_pgd(pgd, va, &level, &ptep);
    assert(rc == 0);
    assert(level == 1);
    rc = lookup_address(va, &level, &ptep);
    assert(rc == 0);
    assert(level == 1);
    rc = pgtable_lookup(pgd, va, false, &ptep);
    assert(rc == 0);
    log_success("Page Table Test Passed");

    return 0;
}
#endif

void pgtable_load_cr3(uint64_t cr3)
{
    physaddr_t pa;
    pa = pgtable_va_to_pa(pte_addr(cr3));
    cr3 &= ~ADDR_MASK;
    cr3 |= PTE_C;
    cr3 |= pa;
    load_cr3(cr3);
}

/**
 * @brief Map a physical page in the page table.
 * @note The page table is linearly mapped to the virtual address space of the process, such that
 * the page table can be accessed by the process. The physical page are marked as vmpl page,
 * and the reference count is set to 0, such that the page can be reclaimed by the process.
 * @param phys The physical address of the page.
 * @retval The virtual address of the page.
 */
pte_t *pgtable_do_mapping(uint64_t phys)
{
    pte_t *va;

    // Check if the page is already mapped
    if (vmpl_page_is_maped(phys)) {
        log_debug("already mapped %lx", phys);
        return __va(phys);
    }

    // Mark the page as vmpl page
    vmpl_page_mark_addr(phys);

    // Map the page to the virtual address space of the process.
    va = do_mapping(dune_fd, phys, PAGE_SIZE);
    if (va == MAP_FAILED) {
        log_err("failed to map pgtable");
        goto failed;
    }

    log_debug("newly mapped phys %lx to %p", phys, va);
    log_debug("content: %lx", *va);

failed:
    return va;
}

/**
 * @brief This function will be called when about to map a physical page to a virtual address.
 * It will update the page table entry of the virtual address to the physical address.
 * @param pgd The page table of the process.
 * @param va The virtual address of the page.
 * @param pte_out The page table entry of the virtual address.
 * @retval 0 on success, -1 on error
 */
int pgtable_lookup(pte_t *root, void *va, int create, pte_t **pte_out)
{
    int m, i, j, k, l;
    pte_t *pgd = root, *p4d, *pud, *pmd, *pte;
    uint64_t pa;

    assert(root != NULL);
    assert(va != NULL);
    assert(pte_out != NULL);

    m = PDX(4, va);
	i = PDX(3, va);
	j = PDX(2, va);
	k = PDX(1, va);
	l = PDX(0, va);

#ifdef CONFIG_PGTABLE_LA57
    log_debug("%p, %d, %d, %d, %d, %d", va, m, i, j, k, l);
    log_debug("pgd[%d] = %lx", m, pgd[m]);
    if (!pte_present(pgd[m])) {
        if (!create)
            return -ENOENT;
        p4d = pgtable_alloc();
        log_debug("p4d = %p", p4d);
        pgd[m] = pte_addr(__pa(p4d)) | PT_DEF_FLAGS;
        log_debug("pgd[%d] = %lx", m, pgd[m]);
    } else {
        p4d = pgtable_do_mapping(pte_addr(pgd[m]));
    }
#else
    log_debug("%p, %d, %d, %d, %d", va, i, j, k, l);
    p4d = pgd;
#endif

    log_debug("p4d[%d] = %lx", i, p4d[i]);
	if (!pte_present(p4d[i])) {
        if (!create)
            return -ENOENT;
        pud = pgtable_alloc();
        p4d[i] = pte_addr(__pa(pud)) | PT_DEF_FLAGS;
    } else {
        pud = pgtable_do_mapping(pte_addr(p4d[i]));
    }

    log_debug("pud[%d] = %lx", j, pud[j]);
	if (!pte_present(pud[j])) {
        if (!create)
            return -ENOENT;
        pmd = pgtable_alloc();
        pud[j] = pte_addr(__pa(pmd)) | PT_DEF_FLAGS;
    } else if (pte_big(pud[j])) {
        *pte_out = &pud[j];
        return 0;
    } else {
        pmd = pgtable_do_mapping(pte_addr(pud[j]));
    }

    log_debug("pmd[%d] = %lx", k, pmd[k]);
	if (!pte_present(pmd[k])) {
        if (!create)
            return -ENOENT;
        pte = pgtable_alloc();
        pmd[k] = pte_addr(__pa(pte)) | PT_DEF_FLAGS;
    } else if (pte_big(pmd[k])) {
        *pte_out = &pmd[k];
        return 0;
    } else {
        pte = pgtable_do_mapping(pte_addr(pmd[k]));
    }

    log_debug("pte[%d] = %lx", l, pte[l]);
	*pte_out = &pte[l];
	return 0;
}

/**
 * @brief This function will be called when about to map a physical page to a virtual address.
 * It will update the page table entry of the virtual address to the physical address.
 * @param pgd The page table of the process.
 * @param va The virtual address of the page.
 * @param pa The physical address of the page.
 * @retval None
 */
int pgtable_update_leaf_pte(pte_t *pgd, uint64_t va, uint64_t pa)
{
	int ret;
	pte_t *ptep;

    ret = pgtable_lookup(pgd, va, false, &ptep);
    if (ret) {
        return ret;
    }

    (*ptep) |= pte_addr(pa) | PTE_DEF_FLAGS;

    return 0;
}

/** 
 * @brief Look up the page table entry of a virtual address in the page table of a process.
 * @param pgd The page table of the process.
 * @param va The virtual address of the page.
 * @param level The level of the page table entry.
 * @param ptep The page table entry of the virtual address.
 * @retval 0 on success, -1 on error
 */
int lookup_address_in_pgd(pte_t *root, uint64_t va, int *level, pte_t **ptep)
{
    int m, i, j, k, l;

    assert(root != NULL);
#ifdef CONFIG_PGTABLE_LA57
    log_debug("%p", va);
    pgd_t *pgd = pgd_offset(root, va);
    if (pte_none(*pgd) || pte_bad(*pgd)) {
        return -EINVAL;
    }

    if (level)
        *level = 5;

    log_debug("pgd: %lx", *pgd);
    p4d_t *p4d = p4d_offset(pgd, va);
#else
    p4d_t *p4d = p4d_offset(root, va);
#endif
    if (pte_none(*p4d) || pte_bad(*p4d)) {
        return -EINVAL;
    }

    if (level)
        *level = 4;

    log_debug("p4d: %lx", *p4d);
    pud_t *pud = pud_offset(p4d, va);
    if (pte_none(*pud) || pte_bad(*pud)) {
        return -EINVAL;
    }

    if (level)
        *level = 3;

    log_debug("pud: %lx", *pud);
    pmd_t *pmd = pmd_offset(pud, va);
    if (pte_none(*pmd) || pte_bad(*pmd)) {
        return -EINVAL;
    }

    if (level)
        *level = 2;

    log_debug("pmd: %lx", *pmd);
    pte_t *pte = pte_offset(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte)) {
        return -EINVAL;
    }

    log_debug("pte: %lx", *pte);
    if (ptep)
        *ptep = pte;

    if (level)
        *level = 1;

    return 0;
}

/**
 * @brief Look up the page table entry of a virtual address in the page table of a process.
 * @param va The virtual address of the page.
 * @param level The level of the page table entry.
 * @param ptep The page table entry of the virtual address.
 */
int lookup_address(uint64_t va, int *level, pte_t **ptep)
{
    if (pgroot == NULL) {
        return -EINVAL;
    }

    return lookup_address_in_pgd(pgroot, va, level, ptep);
}

/**
 * @brief  This function will be called when walking the page table to get the virtual address
 * of the page table. The page table is linearly mapped to the virtual address space of the
 * process, such that the page table can be accessed by the process.
 * @param pa The physical address of the page.
 * @retval The virtual address of the page.
 */
uint64_t pgtable_pa_to_va(uint64_t pa)
{
    assert(pa >= PAGEBASE);
    return phys_to_virt(pa);
}

/**
 * @brief This function will be called when walking the page table to get the physical address
 * of a virtual address. It consists of two parts:
 * 1. If the virtual address is in the range of the page table, then the physical address can be
 * calculated by PA + PGTABLE_MMAP_BASE == VA.
 * 2. If the virtual address is not in the range of the page table, then the physical address can
 * be calculated by the lookup_address function.
 * @param va The virtual address of the page.
 * @retval The physical address of the page.
 */
uint64_t pgtable_va_to_pa(uint64_t va)
{
    pte_t *ptep;

    // XXX: Using PA + PGTABLE_MMAP_BASE == VA
    if ((va >= PGTABLE_MMAP_BASE) && (va < PGTABLE_MMAP_END)) {
        return virt_to_phys(va);
    }

    int rc = pgtable_lookup(pgroot, va, false, &ptep);
    if (rc == 0) {
        return pte_addr(*ptep);
    }

    return 0;
}

/**
 * @brief  Remap a range of virtual address to a range of physical address. This function is used
 * to map the physical memory of the process to the virtual address space of the process.
 * @param  vstart: The start virtual address of the range.
 * @param  vend: The end virtual address of the range.
 * @param  pstart: The start physical address of the range.
 * @retval The number of pages remapped.
 */
long remap_pfn_range(uint64_t vstart, uint64_t vend, uint64_t pstart)
{
    int rc;
    uint64_t va = vstart, pa = pstart;
    long num_pages = 0;

    while (va < vend) {
        pte_t *ptep;
        rc = pgtable_lookup(pgroot, va, true, &ptep);
        if (rc) {
            log_err("Failed to lookup page table entry");
            return rc;
        }

        if (pte_present(*ptep)) {
            log_err("Page table entry already present");
            return -EEXIST;
        }

        *ptep = pfn_pte(pa >> PAGE_SHIFT, PAGE_KERNEL);

        va += PAGE_SIZE;
        pa += PAGE_SIZE;
        num_pages++;
    }

    return num_pages;
}

/**
 * @brief  Remap a range of virtual address to a range of physical address. This function is used
 * to map the physical memory of the process to the virtual address space of the process.
 * @param  vstart: The start virtual address of the range.
 * @param  vend: The end virtual address of the range.
 * @param  pstart: The start physical address of the range.
 */
void remap_va_to_pa(uint64_t vstart, uint64_t vend, uint64_t pstart)
{
    uint64_t va;
    for (va = vstart; va < vend; va += PAGE_SIZE) {
        uint64_t pa = pgtable_va_to_pa(va);
        if (pa == 0) {
            log_err("Failed to get physical address for va: %llx", va);
            return;
        }
        pgtable_update_leaf_pte(pgroot, va, pstart + (va - vstart));
    }
}