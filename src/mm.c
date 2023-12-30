/*
 * mm.c - Virtual memory management routines
 * 堆内存分配主要区分mmap和异常处理两种情况；
 * 可以用自主管理物理内存，接管堆内存的缺页异常；
 * 用自主管理页表页，处理mmap的情况，以及需要用户态clone页表的情况；
 */

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>

#include "mmu.h"
#include "page.h"
#include "pgtable.h"
#include "mm.h"
#include "log.h"

static struct perm_map_t perm_maps[] = {
	{PERM_R, PTE_P},
	{PERM_W, PTE_W},
	{PERM_X, PTE_NX}, // Note: this one is negated
	{PERM_U, PTE_U},
	{PERM_UC, PTE_PCD},
	{PERM_COW, PTE_COW},
	{PERM_USR1, PTE_USR1},
	{PERM_USR2, PTE_USR2},
	{PERM_USR3, PTE_USR3},
	{PERM_BIG, PTE_PS},
	{PERM_BIG_1GB, PTE_PS}
};

static pte_t load_pgroot(void)
{
	uint64_t cr3 = read_cr3();
	return cr3 | PGTABLE_MMAP_BASE;
}

static inline pte_t get_pte_perm(int perm)
{
	pte_t pte_perm = 0;
	int i;

	for (i = 0; i < sizeof(perm_maps) / sizeof(perm_maps[0]); i++) {
		if ((perm & perm_maps[i].perm_flag) != 0) {
			pte_perm |= perm_maps[i].pte_flag;
		}
	}

	// Handle the special case where PERM_X is not set
	if ((perm & PERM_X) == 0) {
		pte_perm |= PTE_NX;
	}

	return pte_perm;
}

static inline struct page * vmpl_va2page(virtaddr_t va)
{
	physaddr_t pa;
	pa = pgtable_va_to_pa(va);
	return vmpl_pa2page(pa);
}

static inline virtaddr_t vmpl_page2va(struct page *pg)
{
	physaddr_t pa;
	pa = vmpl_page2pa(pg);
	return pgtable_pa_to_va(pa);
}

static inline physaddr_t alloc_phys_page(void)
{
	struct page *pg = vmpl_page_alloc(dune_fd);
	if (!pg)
		return NULL;
	return vmpl_page2pa(pg);
}
static inline virtaddr_t alloc_virt_page(void)
{
	struct page *pg = dune_page_alloc(dune_fd);
	if (!pg)
		return NULL;
	return vmpl_page2va(pg);
}

static inline void put_page(void * page)
{
	struct page *pg = vmpl_va2page(page);
	dune_page_put(pg);
}

/**
 * @brief Dune VM Page Walk
 * @note  XXX: Using PA == VA - PGTABLE_MMAP_BASE
 * @param dir The root of the page table.
 * @param start_va The start of the virtual address range to walk.
 * @param end_va The end of the virtual address range to walk.
 * @param cb The callback function to call for each page.
 * @param arg An argument to pass to the callback function.
 * @param level The level of the page table.
 * @param create Whether to create pages if they don't exist.
 */
int __vmpl_vm_page_walk(pte_t *dir, void *start_va, void *end_va,
			page_walk_cb cb, const void *arg, int level,
			int create)
{
	int i, ret;
	int start_idx = PDX(level, start_va);
	int end_idx = PDX(level, end_va);
	void *base_va = (void *) ((unsigned long)
			start_va & ~(PDADDR(level + 1, 1) - 1));

	assert(level >= 0 && level <= NPTLVLS);
	assert(end_idx < NPTENTRIES);

	// Iterate over page table entries in the page table page
	for (i = start_idx; i <= end_idx; i++) {
		void *n_start_va, *n_end_va;
		void *cur_va = base_va + PDADDR(level, i);
		pte_t *pte = &dir[i];

		// Allocate normal page
		if (level == 0) {
			if (create == CREATE_NORMAL || *pte) {
				ret = cb(arg, pte, cur_va);
				if (ret)
					return ret;
			}
			continue;
		}

		// Allocate BIG-2MB page
		if (level == 1) {
			if (create == CREATE_BIG || pte_big(*pte)) {
				ret = cb(arg, pte, cur_va);
				if (ret)
					return ret;
				continue;
			}
		}

		// Allocate BIG-1GB page
		if (level == 2) {
			if (create == CREATE_BIG_1GB || pte_big(*pte)) {
				ret = cb(arg, pte, cur_va);
				if (ret)
					return ret;
				continue;
			}
		}

		// Allocate page table page
		if (!pte_present(*pte)) {
			pte_t *new_pte;

			if (!create)
				continue;
			
			// Allocate page table page
			struct page *page = dune_page_alloc(dune_fd);
			if (!page)
				return -ENOMEM;
			
			// Clear page table page
			physaddr_t pa = dune_page2pa(page);
			new_pte = (pte_t *) pgtable_pa_to_va(pa);
			memset(new_pte, 0, PGSIZE);

			// Update the pte to point to the new page table page
			*pte = PTE_ADDR(pa) | PTE_DEF_FLAGS;
		}

		// Compute start and end virtual addresses for next level
		n_start_va = (i == start_idx) ? start_va : cur_va;
		n_end_va = (i == end_idx) ? end_va : cur_va + PDADDR(level, 1) - 1;

		// Recurse into next level of page table page
		pte_t *new_dir = (pte_t *)pgtable_pa_to_va(PTE_ADDR(*pte));
		ret = __vmpl_vm_page_walk(new_dir, n_start_va, n_end_va, cb, arg,
								  level - 1, create);
		if (ret)
			return ret;
	}

	return 0;
}


/**
 * @brief Dune VM Page Walk
 * Walk the page table, calling the callback function for each page. This function
 * will not update the page table.
 * @param root The root of the page table.
 * @param start_va The start of the virtual address range to walk.
 * @param end_va The end of the virtual address range to walk.
 * @param cb The callback function to call for each page.
 * @param arg An argument to pass to the callback function.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_vm_page_walk(pte_t *root, void *start_va, void *end_va,
		     page_walk_cb cb, const void *arg)
{
	return __vmpl_vm_page_walk(root, start_va, end_va, cb, arg, 3, CREATE_NONE);
}

/**
 * Change the permissions of a virtual memory page.
 * @param arg A pointer to a pte_t structure.
 * @param pte The page table entry to set.
 * @param va The virtual address to change.
 * @return 0 on success, non-zero on failure.
 */
static int __vmpl_vm_mprotect_helper(const void *arg, pte_t *pte, void *va)
{
	pte_t perm = (pte_t) arg;

#ifdef CONFIG_DUNE_DEPRECATED
	// If the page is not present, we can't change the permissions?
	if (!(PTE_FLAGS(*pte) & PTE_P))
		return -ENOMEM;
#endif

	*pte = PTE_ADDR(*pte) | (PTE_FLAGS(*pte) & PTE_PS) | perm;
	return 0;
}

/**
 * @brief Map a virtual memory page to a physical memory page, with the given
 * permissions and flags. A contiguous mapping from va_base to pa_base is
 * created.
 * @param arg A pointer to a map_phys_data_t structure.
 * @param pte The page table entry to set.
 * @param va The virtual address to map.
 * @return 0 on success, non-zero on failure.
 */
static int __vmpl_vm_map_phys_helper(const void *arg, pte_t *pte, void *va)
{
	struct map_phys_data_t *data = (struct map_phys_data_t *) arg;

	*pte = PTE_ADDR(va - data->va_base + data->pa_base) | data->perm;
	return 0;
}

/**
 * Allocate a physical page for a given virtual memory page.
 * @param arg A pointer to a pte_t structure.
 * @param pte The page table entry to set.
 * @param va The virtual address to map.
 */
static int __vmpl_vm_map_pages_helper(const void *arg, pte_t *pte, void *va)
{
	pte_t perm = (pte_t) arg;
	physaddr_t pa = alloc_phys_page();
	if (!pa)
		return -ENOMEM;

	*pte = PTE_ADDR(pa) | perm;

	return 0;
}

/**
 * Clone a page table entry.
 * @param arg A pointer to a pte_t structure.
 * @param pte The page table entry to set.
 * @param va The virtual address to map.
 * @return 0 on success, non-zero on failure.
 */
static int __vmpl_vm_clone_helper(const void *arg, pte_t *pte, void *va)
{
	int ret;
	pte_t *newRoot = (pte_t *)arg;
	pte_t *newPte;

	// Create new page table entry for the new page table root
	ret = pgtable_create(newRoot, va, &newPte);
	if (ret < 0)
		return ret;

	// Refcount the physical page
	vmpl_page_get_addr(PTE_ADDR(*pte));

	// Copy the page table entry
	*newPte = *pte;

	return 0;
}

/**
 * Free a page table entry.
 * @param arg A pointer to a pte_t structure.
 * @param pte The page table entry to set.
 * @param va The virtual address to map.
 * @return 0 on success, non-zero on failure.
 */
static int __vmpl_vm_free_helper(const void *arg, pte_t *pte, void *va)
{
	// Refcount the physical page
	vmpl_page_put_addr(PTE_ADDR(*pte));

	// Invalidate mapping
	*pte = 0;

	return 0;
}


/**
 * Map a virtual memory page to a physical memory page, with the given
 * permissions and flags.
 * @param root The root of the page table.
 * @param va The virtual address to map.
 * @param len The length of the mapping.
 * @param pa The physical address to map.
 * @param perm The permissions to set.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_vm_map_phys(pte_t *root, void *va, size_t len, void *pa, int perm)
{
	int ret;
	struct map_phys_data_t data;
	int create;

#ifdef CONFIG_DUNE_DEPRECATED
	if (!(perm & PERM_R) && (perm & ~(PERM_R)))
		return -EINVAL;
#endif

	data.perm = get_pte_perm(perm);
	data.va_base = (unsigned long) va;
	data.pa_base = (unsigned long) pa;

	if (perm & PERM_BIG)
		create = CREATE_BIG;
	else if (perm & PERM_BIG_1GB)
		create = CREATE_BIG_1GB;
	else
		create = CREATE_NORMAL;

	ret = __vmpl_vm_page_walk(root, va, va + len - 1,
							  &__vmpl_vm_map_phys_helper,
							  (void *)&data, 3, create);
	if (ret)
		return ret;

	return 0;
}

/**
 * Map virtual memory pages with the given permissions and flags.
 * @note Note: len must be a multiple of PGSIZE.
 * @param root The root of the page table.
 * @param va The virtual address to map.
 * @param len The length of the mapping.
 * @param perm The permissions to set.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_vm_map_pages(pte_t *root, void *va, size_t len, int perm)
{
	int ret;
	pte_t pte_perm;

	// Check permissions are valid (must have at least one of R, W, X)
	if (!(perm & PERM_R) && (perm & ~(PERM_R)))
		return -EINVAL;

	pte_perm = get_pte_perm(perm);

	ret = __vmpl_vm_page_walk(root, va, va + len - 1,
							  &__vmpl_vm_map_pages_helper,
							  (void *)pte_perm, 3, CREATE_NORMAL);

	return ret;
}

/**
 * This is a prologure before redirecting `mmap` to the guest OS.
 * It is used to ensure that all the pgtable pages are linearly mapped in the
 * vmpl-process address space.
 */
void *vmpl_vm_mmap(pte_t *root, void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	void *ret;
	int rc;

	__vmpl_vm_page_walk(root, VA_START, VA_END,
			&__vmpl_vm_map_pages_helper, root,
			3, CREATE_NONE);

	return ret;
}

/**
 * This is a prologure before redirecting `munmap` to the guest OS.
 */
void vmpl_vm_unmap(pte_t *root, void *va, size_t len)
{
	/* FIXME: Doesn't free as much memory as it could */
	__vmpl_vm_page_walk(root, va, va + len - 1,
			&__vmpl_vm_free_helper, NULL,
			3, CREATE_NONE);

	vmpl_flush_tlb();
}

/**
 * @brief This is a prologure before redirecting `mremap` to the guest OS.
 * @note Note: This function is not implemented.
 */
void *vmpl_vm_mremap(pte_t *root, void *old_address, size_t old_size,
					 size_t new_size, int flags, void *new_address)
{
	void *ret;
	int rc;

	return ret;
}

/**
 * This is a prologure before redirecting `mprotect` to the guest OS.
 */
int vmpl_vm_mprotect(pte_t *root, void *va, size_t len, int perm)
{
	int ret;
	pte_t pte_perm;

	if (!(perm & PERM_R)) {
		if (perm & PERM_W)
			return -EINVAL;
		perm = PERM_NONE;
	}

	pte_perm = get_pte_perm(perm);

	ret = __vmpl_vm_page_walk(root, va, va + len - 1,
							  &__vmpl_vm_mprotect_helper,
							  (void *)pte_perm, 3, CREATE_NONE);
	if (ret)
		return ret;

	vmpl_flush_tlb();

	return 0;
}

/**
 * Clone a page root.
 */
pte_t *vmpl_vm_clone(pte_t *root)
{
       int ret;
       pte_t *newRoot;

       newRoot = alloc_virt_page();
       memset(newRoot, 0, PGSIZE);

       ret = __vmpl_vm_page_walk(root, VA_START, VA_END,
                       &__vmpl_vm_clone_helper, newRoot,
                       3, CREATE_NONE);
       if (ret < 0) {
               vmpl_vm_free(newRoot);
               return NULL;
       }

       return newRoot;
}

/**
 * Free the page table and decrement the reference count on any pages.
 */
void vmpl_vm_free(pte_t *root)
{
	// XXX: Should only need one page walk
	// XXX: Hacky - Until I fix ref counting
#ifdef CONFIG_DUNE_DEPRECATED
	__vmpl_vm_page_walk(root, VA_START, VA_END,
			&__vmpl_vm_free_helper, NULL,
			3, CREATE_NONE);
#endif

	__vmpl_vm_page_walk(root, VA_START, VA_END,
			&__vmpl_vm_free_helper, NULL,
			2, CREATE_NONE);

	__vmpl_vm_page_walk(root, VA_START, VA_END,
			&__vmpl_vm_free_helper, NULL,
			1, CREATE_NONE);

	put_page(root);

	return;
}

/**
 * Handle a page fault.
 * This function should be called from the page fault handler.
 * @param addr The address that caused the page fault.
 * @param fec The fault error code.
 * @return 0 on success, non-zero on failure.
 */
void vmpl_vm_default_pgflt_handler(uintptr_t addr, uint64_t fec)
{
	pte_t *pte = NULL;
	int rc;

	/*
	 * Assert on present and reserved bits.
	 */
	assert(!(fec & (FEC_P | FEC_RSV)));

	pte_t pgroot = load_pgroot();
	rc = pgtable_lookup(pgroot, (void *)addr, &pte);
	assert(rc == 0);

	if ((fec & FEC_W) && (*pte & PTE_COW)) {
		void *newPage;
		struct page *pg = vmpl_pa2page(PTE_ADDR(*pte));
		pte_t perm = PTE_FLAGS(*pte);

		// Compute new permissions
		perm &= ~PTE_COW;
		perm |= PTE_W;

		// Check if we can just change permissions
		if (vmpl_page_isfrompool(PTE_ADDR(*pte)) && pg->ref == 1) {
			*pte = PTE_ADDR(*pte) | perm;
			return;
		}

		// Duplicate page
		newPage = alloc_virt_page();
		memcpy(newPage, (void *)PGADDR(addr), PGSIZE);

		// Decrement ref count on old page
		vmpl_page_put_addr(PTE_ADDR(*pte));

		// Map page
		physaddr_t pa = pgtable_va_to_pa(newPage);
		*pte = PTE_ADDR(pa) | perm;

		// Invalidate
		vmpl_flush_tlb_one(addr);
	}
}

/**
 * Initialize the virtual memory subsystem.
 * This function should be called before any other vmpl_vm_* functions.
 * @param vmpl_vm The vmpl_vm_t structure to initialize.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_vm_init(struct vmpl_vm_t *vmpl_vm) {
    FILE *maps_file;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
    size_t heap_start, heap_end;

    maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        perror("fopen");
        return 1;
    }

	vmpl_vm->heap_start = 0;
    vmpl_vm->heap_end = 0;
	vmpl_vm->linear_start = PGTABLE_MMAP_BASE;
	vmpl_vm->linear_end = PGTABLE_MMAP_END;
	vmpl_vm->mmap_start = 0;
	vmpl_vm->mmap_end = 0;

	while ((read = getline(&line, &len, maps_file)) != -1) {
        if (strstr(line, "[heap]")) {
            if (sscanf(line, "%lx - %lx", &heap_start, &heap_end) == 2) {
                log_debug("Heap range: %lx-%lx", heap_start, heap_end);
                if (vmpl_vm->heap_start == 0) {
                    vmpl_vm->heap_start = heap_start;
                }
                if (vmpl_vm->heap_end < heap_end) {
                    vmpl_vm->heap_end = heap_end;
                }
            }
        }
		if (strstr(line, "[stack]")) {
			if (sscanf(line, "%lx - %lx", &vmpl_vm->stack_start, &vmpl_vm->stack_end) == 2) {
				log_debug("Stack range: %lx-%lx", vmpl_vm->stack_start, vmpl_vm->stack_end);
			}
		}
    }

    log_info("Heap range: %lx-%lx", vmpl_vm->heap_start, vmpl_vm->heap_end);

    fclose(maps_file);
    return 0;
}