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
#include "sys.h"
#include "ioctl.h"
#include "sev.h"
#include "log.h"
#include "mmu.h"
#include "page.h"
#include "pgtable.h"
#include "layout.h"
#include "vmpl.h"

#define MEMORY_POOL_START   PGTABLE_MMAP_BASE
#define MEMORY_POOL_END     PGTABLE_MMAP_END

// 使用pgtable的地址转换函数
#define __va(x) pgtable_pa_to_va(x)
#define __pa(x) pgtable_va_to_pa(x)

// 使用pgtable的地址转换函数
#define phys_to_virt(x) pgtable_pa_to_va(x)
#define virt_to_phys(x) pgtable_va_to_pa(x)

#define padding(level) ((PT_LEVEL_PGD - level)*4 + 4)
static char *pt_names[] = { 
#ifdef CONFIG_PGTABLE_LA57
    "PTE", "PMD", "PUD", "P4D", "PGD"
#else
    "PTE", "PMD", "PUD", "P4D"
#endif
};
pte_t *pgroot;

static inline virtaddr_t alloc_zero_page(void)
{
	struct page *pg;
	physaddr_t pa;
	virtaddr_t va;

	pg = dune_page_alloc();
	if (!pg)
		return NULL;
	
	pa = dune_page2pa(pg);
	va = phys_to_virt(pa);
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
    if ((level + 1) == PT_LEVEL_PTE) {
        (*page_count)++;
        return 0;
    }

    // Map page table to virtual address space
    vaddr = do_mapping(paddr, PAGE_SIZE);
    if (vaddr == MAP_FAILED) {
        perror("dune: failed to map pgtable");
        goto failed;
    }

    // Traverse page table
    log_trace("%*s%s [%p - %09lx]", padding(level), "", pt_names[level], vaddr, paddr);
#ifdef CONFIG_PGTABLE_LA57
    max_i = (level != PT_LEVEL_PGD) ? 512 : 256;
#else
    max_i = (level != PT_LEVEL_P4D) ? 512 : 256;
#endif
    for (int i = 0; i < max_i; i++) {
        pte_t pte = vaddr[i];
        if (pte_present(pte)) {
            log_trace("%*s%s Entry[%d]: %016lx", padding(level), "", pt_names[level], i, pte);
            __pgtable_init(pte_addr(pte), level - 1, fd, pgtable_count, page_count);
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
#ifdef CONFIG_PGTABLE_LA57
	rc = __pgtable_init(cr3, PT_LEVEL_PGD, fd, &pgtable_count, &page_count);
#else
	rc = __pgtable_init(cr3, PT_LEVEL_P4D, fd, &pgtable_count, &page_count);
#endif
    if (rc) {
        log_err("pgtable init failed");
        return rc;
    }

    log_debug("dune: %lu page tables, %lu pages", pgtable_count, page_count);
    *pgd = phys_to_virt(cr3);
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

void load_cr3(uint64_t cr3)
{
    physaddr_t pa;
    pa = virt_to_phys(pte_addr(cr3));
    cr3 &= ~ADDR_MASK;
    cr3 |= PTE_C;
    cr3 |= pa;
    native_load_cr3(cr3);
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
        return phys_to_virt(phys);
    }

    // Mark the page as vmpl page
    vmpl_page_mark_addr(phys);

    // Map the page to the virtual address space of the process.
    va = do_mapping(phys, PAGE_SIZE);
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
    pte_t *pt_curr = root;
    uint64_t idx;
    enum page_level level;
    
    assert(root != NULL);
    assert(va != NULL);
    assert(pte_out != NULL);

    // 从最高级页表开始遍历
#ifdef CONFIG_PGTABLE_LA57
    for (level = PT_LEVEL_PGD; level >= PT_LEVEL_PTE; level--) {
#else
    for (level = PT_LEVEL_P4D; level >= PT_LEVEL_PTE; level--) {
#endif
        idx = PDX(level, va);
        pte_t pte = pt_curr[idx];
        log_debug("level %d: pt_curr[%lu] = %lx", level, idx, pte);

        if (!pte_present(pte)) {
            if (create == CREATE_NONE)
                return -ENOENT;
                
            // 需要创建新的页表页
            pte_t *new_pt = alloc_zero_page();
            if (!new_pt)
                return -ENOMEM;
                
            pt_curr[idx] = pte_addr(pgtable_va_to_pa(new_pt)) | PTE_DEF_FLAGS;
            log_debug("created new pt at level %d: %lx", level, pt_curr[idx]);

            // 根据创建模式处理
            if ((create == CREATE_BIG && level == PT_LEVEL_PMD) ||
                (create == CREATE_BIG_1GB && level == PT_LEVEL_PUD)) {
                log_debug("big page at level %d: %lx", level, pt_curr[idx]);
                // 对于大页，直接返回当前页表项
                *pte_out = &pt_curr[idx];
                return 0;
            }

            // 下一级页表
            pt_curr = new_pt;
        } else {
            // 检查是否是大页
            if ((level == PT_LEVEL_PMD && pte_big(pte)) ||
                (level == PT_LEVEL_PUD && pte_big(pte))) {
                // 返回当前页表项
                log_debug("big page at level %d: %lx", level, pte);
                *pte_out = &pt_curr[idx];
                return 0;
            }

            // 获取下一级页表的虚拟地址
            pt_curr = pgtable_do_mapping(pte_addr(pte));
            if (!pt_curr)
                return -EFAULT;
        }
    }

    *pte_out = &pt_curr[idx];
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
    pte_t *pt_curr;
    enum page_level curr_level;
    uint64_t idx;

    assert(root != NULL);

    pt_curr = root;
#ifdef CONFIG_PGTABLE_LA57
    curr_level = PT_LEVEL_PGD;
#else
    curr_level = PT_LEVEL_P4D;
#endif

    // 从最高级页表开始遍历
    while (curr_level >= PT_LEVEL_PTE) {
        idx = PDX(curr_level, va);
        log_debug("level %d: pt_curr[%lu] = %lx", curr_level, idx, pt_curr[idx]);

        // 检查页表项是否有效
        if (pte_none(pt_curr[idx]) || 
            (curr_level > PT_LEVEL_PTE && pte_bad(pt_curr[idx])) ||
            (curr_level == PT_LEVEL_PTE && !pte_present(pt_curr[idx]))) {
            return -EINVAL;
        }

        // 更新返回值
        if (level) {
            *level = curr_level;
        }
        if (curr_level == PT_LEVEL_PTE) {
            if (ptep) {
                *ptep = &pt_curr[idx];
            }
            break;
        }

        // 获取下一级页表
        pt_curr = pgtable_do_mapping(pte_addr(pt_curr[idx]));
        if (!pt_curr) {
            return -EFAULT;
        }

        curr_level--;
    }

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
    const address_mapping_t *mapping = get_current_mapping();
    
    if (mapping->is_valid_pa(pa)) {
        return mapping->pa_to_va(pa);
    }

    return 0;
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
    const address_mapping_t *mapping = get_current_mapping();
    
    // 如果地址在页表映射范围内，使用页表查找
    if (mapping->is_valid_va(va)) {
        return mapping->va_to_pa(va);
    }

    // 否则通过页表查找
    pte_t *ptep;
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