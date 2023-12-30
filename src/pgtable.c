#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>

#include "vmpl-dev.h"
#include "vmpl-ioctl.h"
#include "sev.h"
#include "log.h"
#include "bitmap.h"
#include "pgtable.h"

#define MEMORY_POOL_START 0x140000000
#define MEMORY_POOL_END 0x170000000

#define __va(x) ((void *)((unsigned long)(x) + PGTABLE_MMAP_BASE))
#define __pa(x) ((unsigned long)(x) - PGTABLE_MMAP_BASE)
#define phys_to_virt(x) __va(x)
#define virt_to_phys(x) __pa(x)

#define padding(level) ((level)*4 + 4)
static char *pt_names[] = { "PML4", "PDP", "PD", "PT", "Page" };
static __thread uint64_t *this_pgd;
static void *free_pages;

#define __pgtable_map(paddr, fd)                         \
    mmap((void *)(PGTABLE_MMAP_BASE + paddr), PAGE_SIZE, \
         PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 0)

/**
 * @brief  Setup page table self-mapping
 * @note   采用广度优先遍历的方式，遍历每一个页表项，将进程物理内存页的vmpl属性标记为1，增加引用计数，
 * 这样就可以自行回收物理页了。对于满足vmpl=1，refcount=1的物理页，都可以纳入到空闲页链表中。
 * 而对于map过的物理页，vmpl=1，refcount=1
 * @param  paddr: Physical address of the page table
 * @param  level: Level of the page table
 * @param  fd: File descriptor of the vmpl-dev
 * @retval 
 */
static int __pgtable_init(uint64_t paddr, int level, int fd, int *pgtable_count)
{
    size_t max_i;
    uint64_t *vaddr;

    if (level == 4)
        return 0;

    bitclr(paddr, 63);
    bitclr(paddr, 51);

    vaddr = __pgtable_map(paddr, fd);
    if (vaddr == MAP_FAILED) {
        perror("dune: failed to map pgtable");
        goto failed;
    }

    log_trace("%*s%s [%p - %09lx]", padding(level), "", pt_names[level], vaddr, paddr);
    max_i = (level != 0) ? 512 : 256;
    for (int i = 0; i < max_i; i++) {
        if (vaddr[i] & 0x1) {
            log_trace("%*s%s Entry[%d]: %016lx", padding(level), "", pt_names[level], i, vaddr[i]);
            __pgtable_init(pte_addr(vaddr[i]), level + 1, fd, pgtable_count);
        }
    }

    (*pgtable_count)++; // Increment page count

    return 0;
failed:
    return -ENOMEM;
}

#ifdef CONFIG_VMPL_PGTABLE_ALLOC
/**
 * @brief  Update page table entry with the given virtual address
 * @note   Preallocate page table pages, and map them to the virtual address space
 * @param  fd: File descriptor of the vmpl-dev
 * @retval 0 on success, -1 on failure
 */
static int __pgtable_update(int fd)
{
    int rc;
    pte_t *ptep;
    uint64_t *base, *p, *vaddr;
    uint64_t paddr;
    log_debug("pgtable update");

    // preallocate page table pages
    base = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, NULL, 0);

    // for each page, obtain the physical address, and map it to the virtual address space
    for (p = base; p < base + PAGE_SIZE; p += PAGE_SIZE / sizeof(*p)) {
        // obtain the physical address of the page
        rc = lookup_address((uint64_t)p, NULL, &ptep);
        if (rc) {
            log_err("lookup address failed");
            goto failed;
        }

        paddr = pte_addr(*ptep);
        // map the page table page to the virtual address space
        vaddr = mmap((void *)(PGTABLE_MMAP_BASE + paddr), PAGE_SIZE,
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, 0);
        if (vaddr == MAP_FAILED) {
            perror("dune: failed to map pgtable");
            goto failed;
        }
    }

	return 0;
failed:
	return -ENOMEM;
}
#endif

int pgtable_init(uint64_t **pgd, int fd)
{
	int rc;
    uint64_t cr3;
	size_t pgtable_count = 0;
	log_debug("pgtable init");

	// Get CR3
    rc = vmpl_ioctl_get_cr3(fd, &cr3);
    if (rc) {
        log_err("get cr3 failed");
        return rc;
    }

    log_debug("dune: CR3 at 0x%lx", cr3);

    // Initialize page table
	rc = __pgtable_init(cr3, 0, fd, &pgtable_count);
    if (rc) {
        log_err("pgtable init failed");
        return rc;
    }

    log_debug("dune: %lu page tables", pgtable_count);
    *pgd = (uint64_t *)(PGTABLE_MMAP_BASE + cr3);
    this_pgd = *pgd;

#ifdef CONFIG_VMPL_PGTABLE_ALLOC
    // Update page table
    rc = __pgtable_update(fd);
    if (rc) {
        log_err("pgtable update failed");
        return rc;
    }
#endif

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

#ifdef CONFIG_VMPL_PGTABLE_ALLOC
/**
 * https://www.kernel.org/doc/Documentation/vm/pagemap.txt
 */
uint64_t pgtable_va_to_pa(uint64_t vaddr)
{
    uint64_t phys_addr;
    int mem_fd = open("/proc/self/pagemap", O_RDONLY);
    if (mem_fd < 0) {
        log_err("open /proc/self/pagemap failed");
        return 0;
    }

    uint64_t virt_addr = (uint64_t)virt_addr;
    uint64_t offset = (virt_addr >> PAGE_SHIFT) * sizeof(uint64_t);

    if (lseek(mem_fd, offset, SEEK_SET) == -1) {
        log_err("lseek failed");
        return 0;
    }

    uint64_t read_val;
    if (read(mem_fd, &read_val, sizeof(uint64_t)) != sizeof(uint64_t)) {
        log_err("read failed");
        return 0;
    }

    if (!(read_val & (1ULL << 63))) {
        log_err("page not present");
        return 0;
    }

    phys_addr = read_val & ((1ULL << 54) - 1);
    close(mem_fd);
    return phys_addr;
}

/**
 * @brief  Clone page table
 * @note   
 * @param  dst_pgd: Destination page table
 * @param  src_pgd: Source page table
 * @param  level: Level of the page table
 * @retval 
 */
int __pgtable_clone(uint64_t *dst_pgd, uint64_t *src_pgd, uint64_t level)
{
    int rc = 0;
    uint64_t *src_pgd_entry, *dst_pgd_entry;
    log_debug("pgtable clone");
    if (level == 0) {
        return 0;
    }

    dst_pgd_entry = (uint64_t *)pmm_alloc_page(1);
    if (dst_pgd_entry == NULL) {
        log_err("pmm alloc failed");
        return -ENOMEM;
    }

    *dst_pgd_entry = *src_pgd;
    *dst_pgd = (uint64_t)dst_pgd_entry;

    *src_pgd_entry = (uint64_t *)phys_to_virt(*src_pgd);
    *dst_pgd_entry = (uint64_t *)phys_to_virt(*dst_pgd);

    for (int i = 0; i < 512; i++) {
        if (src_pgd_entry[i] & 0x1) {
            rc = __pgtable_clone(&dst_pgd_entry[i], &src_pgd_entry[i], level - 1);
            if (rc) {
                log_err("pgtable clone failed");
                return rc;
            }
        }
    }

    return 0;
}

int pgtable_clone(uint64_t *dst_pgd, uint64_t *src_pgd)
{
    int rc = 0;
    log_debug("pgtable clone");
    rc = __pgtable_clone(dst_pgd, src_pgd, 4);
    if (rc) {
        log_err("pgtable clone failed");
        return rc;
    }

    return 0;
}
#endif

int lookup_address_in_pgd(uint64_t *pgd, uint64_t va, int *level, pte_t **ptep)
{
    pml4e_t *pml4e = pml4_offset(pgd, va);
    if (pml4e_none(*pml4e) || pml4e_bad(*pml4e)) {
        return -EINVAL;
    }

    if (level)
        *level = 4;

    pdpe_t *pdpe = pdp_offset(pml4e, va);
    if (pdpe_none(*pdpe) || pdpe_bad(*pdpe)) {
        return -EINVAL;
    }

    if (level)
        *level = 3;

    pde_t *pde = pd_offset(pdpe, va);
    if (pde_none(*pde) || pde_bad(*pde)) {
        return -EINVAL;
    }

    if (level)
        *level = 2;

    pte_t *pte = pte_offset(pde, va);
    if (pte_none(*pte) || !pte_present(*pte)) {
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
    if (this_pgd == NULL) {
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
    pte_t *ptep;
    int level;

    if ((va > PGTABLE_MMAP_BASE) && (va < PGTABLE_MMAP_BASE + PGTABLE_MMAP_SIZE)) {
        return virt_to_phys(va);
    } else {
        int rc = lookup_address(va, &level, &ptep);
        if (rc) {
            return 0;
        }
    }

    return pte_addr(*ptep);
}

static void update_leaf_pte(uint64_t *pgd, uint64_t va, uint64_t pa)
{
	int ret;
	pte_t *ptep;
	int level;

    ret = lookup_address_in_pgd(pgd, va, &level, &ptep);
    if (ret) {
        return;
    }

    (*ptep) |= pa >> PAGE_SHIFT;
}

static long remap_pfn_range(uint64_t vstart, uint64_t vend, uint64_t pa)
{
    size_t nr_pages = (vend - vstart) >> PAGE_SHIFT;
    for (size_t i = 0; i < nr_pages; i++) {
        update_leaf_pte(this_pgd, vstart + i * PAGE_SIZE, pa + i * PAGE_SIZE);
    }
}

void remap_va_to_pa(uint64_t va_start, uint64_t va_end, uint64_t pa_start)
{
    uint64_t va;
    for (va = va_start; va < va_end; va += PAGE_SIZE) {
        uint64_t pa = pgtable_va_to_pa(va);
        if (pa == 0) {
            log_err("Failed to get physical address for va: %llx", va);
            return;
        }
        update_leaf_pte(this_pgd, va, pa_start + (va - va_start));
    }
}