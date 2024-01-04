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
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>

#include "mmu.h"
#include "vmpl-ioctl.h"
#include "page.h"
#include "vma.h"
#include "vm.h"
#include "mm.h"
#include "log.h"

#define VMPL_VM_MAP_PHYS_FMT	"start = 0x%lx, end = 0x%lx, perm = 0x%lx"
#define VMPL_VM_MAP_PAGES_FMT	"start = 0x%lx, end = 0x%lx, perm = 0x%lx"
#define VMPL_VM_MMAP_FMT		"start = 0x%lx, end = 0x%lx, perm = 0x%lx, flags = 0x%lx, fd = %d, offset = 0x%lx"
#define VMPL_VM_MREMAP_FMT		"old_start = 0x%lx, old_end = 0x%lx, new_start = 0x%lx, new_end = 0x%lx, perm = 0x%lx"
#define VMPL_VM_MUNMAP_FMT		"start = 0x%lx, end = 0x%lx"
#define VMPL_VM_MPROTECT_FMT	"start = 0x%lx, end = 0x%lx, perm = 0x%lx"
#define VMPL_VM_CLONE_FMT		"start = 0x%lx, end = 0x%lx, prot = 0x%lx, path = 0x%lx"

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
	physaddr_t pa = pgtable_va_to_pa(va);
	assert(pa != 0);
	return vmpl_pa2page(pa);
}

static inline virtaddr_t vmpl_page2va(struct page *pg)
{
	physaddr_t pa = vmpl_page2pa(pg);
	
	return pgtable_pa_to_va(pa);
}

static inline physaddr_t alloc_phys_page(void)
{
	struct page *pg = vmpl_page_alloc(dune_fd);
	if (!pg)
		return NULL;
	return vmpl_page2pa(pg);
}

static inline void free_phys_page(physaddr_t pa)
{
	struct page *pg = vmpl_pa2page(pa);
	vmpl_page_free(pg);
}

static inline virtaddr_t alloc_virt_page(void)
{
	struct page *pg = dune_page_alloc(dune_fd);
	if (!pg)
		return NULL;
	return vmpl_page2va(pg);
}

static inline void free_virt_page(virtaddr_t va)
{
	struct page *pg = vmpl_va2page(va);
	dune_page_free(pg);
}

static inline void get_page(void * page)
{
	struct page *pg = vmpl_va2page(page);
	dune_page_get(pg);
}

static inline void put_page(void * page)
{
	struct page *pg = vmpl_va2page(page);
	dune_page_put(pg);
}

/**
 * @brief Dune VM Page Walk
 * @note  XXX: Using PA == VA - PGTABLE_MMAP_BASE
 * The page walk callback function takes a page table entry and a virtual address.
 * @param dir The root of the page table.
 * @param start_va The start of the virtual address range to walk.
 * @param end_va The end of the virtual address range to walk.
 * @param cb The callback function to call for each page.
 * @param arg An argument to pass to the callback function.
 * @param level The level of the page table.
 * @param create Whether to create pages if they don't exist.
 * @retval 0 on success, non-zero on failure.
 */
int __vmpl_vm_page_walk(pte_t *dir, void *start_va, void *end_va,
			page_walk_cb cb, const void *arg, int level,
			int create)
{
	int i, ret;
	pte_t *new_dir;
	int start_idx = PDX(level, start_va);
	int end_idx = PDX(level, end_va);
	void *base_va = (void *) ((unsigned long)
			start_va & ~(PDADDR(level + 1, 1) - 1));

	assert(level >= 0 && level <= NPTLVLS);
	assert(end_idx < NPTENTRIES);

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
			if (!create)
				continue;

			new_dir = alloc_virt_page();
			if (!new_dir)
				return -ENOMEM;
			memset(new_dir, 0, PGSIZE);

			uint64_t pa = pgtable_va_to_pa(new_dir);
			*pte = pte_addr(pa) | PTE_DEF_FLAGS;
		} else {
			new_dir = pgtable_do_mapping(pte_addr(*pte));
		}

		n_start_va = (i == start_idx) ? start_va : cur_va;
		n_end_va = (i == end_idx) ? end_va : cur_va + PDADDR(level, 1) - 1;

		ret = __vmpl_vm_page_walk(new_dir, n_start_va, n_end_va, cb, arg,
								  level - 1, create);
		if (ret)
			return ret;
	}

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

static int __vmpl_vm_mmap_helper(const void *arg, pte_t *pte, void *va)
{
	pte_t perm = (pte_t) arg;
	physaddr_t pa = alloc_phys_page();
	if (!pa)
		return -ENOMEM;

	*pte = PTE_ADDR(pa) | perm;

	return 0;
}

static int __vmpl_vm_mremap_helper(const void *arg, pte_t *pte, void *va)
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
	ret = pgtable_lookup(newRoot, va, true, &newPte);
	if (ret < 0)
		return ret;

	// Refcount the physical page
	vmpl_page_get_addr(pte_addr(*pte));

	// Copy the page table entry
	*newPte = *pte;

	return 0;
}

static inline __vmpl_vm_munmap_helper(const void *arg, pte_t *pte, void *va)
{
	// Refcount the physical page
	vmpl_page_put_addr(pte_addr(*pte));

	// Invalidate mapping
	*pte = 0;

	return 0;
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

	*pte = pte_addr(*pte) | (PTE_FLAGS(*pte) & PTE_PS) | perm;
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
	vmpl_page_put_addr(pte_addr(*pte));

	// Invalidate mapping
	*pte = 0;

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
 * @brief This is a prologure before redirecting `mmap` to the guest OS.
 * @note Note: This function is not implemented.
 * @param root The root of the page table.
 * @param addr The address to map.
 * @param length The length of the mapping.
 * @param prot The permissions to set.
 * @param flags The flags to set.
 * @param fd The file descriptor to map.
 * @param offset The offset into the file.
 * @return 0 on success, non-zero on failure.
 */
void *vmpl_vm_mmap(pte_t *root, void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	uint64_t va_start, va_end;
	struct vmpl_vma_t *vma;
	int rc;

	log_debug(VMPL_VM_MMAP_FMT, addr, addr + length - 1, prot, flags, fd, offset);
	// Check that the address is not NULL
	if (addr) {
		addr = (void *)PAGE_ALIGN_DOWN((uintptr_t)addr);
		length = PAGE_ALIGN_UP(length);
	}

	// Filter out unsupported flags
	if (flags & (MAP_SHARED | MAP_FIXED | MAP_GROWSDOWN | MAP_STACK | MAP_HUGETLB))
		return MAP_FAILED;

	// Filter out unsupported file-backed mappings
	if (fd != -1)
		return MAP_FAILED;

	// Check that the address range is not already mapped
	va_start = (uint64_t)addr;
	va_end = va_start + length;
	vma = find_vma_intersection(&vmpl_mm, va_start, va_end);
	if (vma != NULL) {
		errno = EEXIST;
		return MAP_FAILED;
	}

	// Check that the address range belongs to the VMPL VM
	if (va_end <= vmpl_mm.vmpl_vm.va_start || va_start > vmpl_mm.vmpl_vm.va_start) {
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Find unused address range
	vma = alloc_vma(&vmpl_mm, length);
	if (vma == NULL) {
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Insert VMA into VMPL-VM
	vma->prot = prot;
	vma->flags = flags;
	vma->offset = offset;
	vma->path = NULL;
	rc = insert_vma(&vmpl_mm.vmpl_vm, vma);
	if (rc != 0) {
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Handle anonymous mappings
	log_debug("vma->start = 0x%lx, vma->end = 0x%lx", vma->start, vma->end);
	__vmpl_vm_page_walk(vmpl_mm.pgd, vma->start, vma->end,
			&__vmpl_vm_map_pages_helper, vma,
			3, CREATE_NONE);

	return (void *)vma->start;
}

/**
 * @brief This is a prologure before redirecting `mremap` to the guest OS.
 * @note Note: This function is not implemented.
 * @param root The root of the page table.
 * @param old_address The old address.
 * @param old_size The old size.
 * @param new_size The new size.
 * @param flags The flags to set.
 * @param new_address The new address.
 * @return 0 on success, non-zero on failure.
 */
void *vmpl_vm_mremap(pte_t *root, void *old_address, size_t old_size,
					 size_t new_size, int flags, void *new_address)
{
	void *ret;
	int rc;

	// Align old address and size
	if (old_address) {
		old_address = (void *)PAGE_ALIGN_DOWN((uintptr_t)old_address);
		old_size = PAGE_ALIGN_UP(old_size);
	}

	// Align new address and size
	if (new_address) {
		new_address = (void *)PAGE_ALIGN_DOWN((uintptr_t)new_address);
		new_size = new_size ? PAGE_ALIGN_UP(new_size) : old_size;
	}

	log_debug(VMPL_VM_MREMAP_FMT, old_address, old_address + old_size,
			  new_address, new_address + new_size, flags);

	// Check that the old address range belongs to the VMPL VM
	if ((old_address + old_size) <= vmpl_mm.vmpl_vm.va_start ||
		 old_address > vmpl_mm.vmpl_vm.va_end) {
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Check that the old address range is mapped
	rc = find_vma_intersection(&vmpl_mm, old_address, old_size);
	if (rc == NULL) {
		errno = ENOMEM;
		return MAP_FAILED;
	}


	// Check that the new address range is not already mapped
	rc = find_vma_intersection(&vmpl_mm, new_address, new_size ? new_size : old_size);
	if (rc != NULL) {
		errno = EEXIST;
		return MAP_FAILED;
	}

	// Unsupported flags, (FIXME: Support these flags)
	if (flags & (MAP_FIXED | MAP_GROWSDOWN | MAP_STACK | MAP_HUGETLB))
		return MAP_FAILED;



	// TODO. Handle anonymous mappings
	return MAP_FAILED;
}

/**
 * @brief Unmap virtual memory pages.
 * @note Note: len must be a multiple of PGSIZE.
 * @param root The root of the page table.
 * @param addr The virtual address to unmap.
 * @param length The length of the mapping.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_vm_munmap(pte_t *root, void *addr, size_t length)
{
	log_debug(VMPL_VM_MUNMAP_FMT, addr, addr + length - 1);

	/* FIXME: Doesn't free as much memory as it could */
	__vmpl_vm_page_walk(root, addr, addr + length - 1,
						&__vmpl_vm_free_helper, NULL,
						3, CREATE_NONE);

	vmpl_flush_tlb();

	return 0;
}

/**
 * @brief Change the permissions of virtual memory pages.
 * @note Note: len must be a multiple of PGSIZE.
 * @param root The root of the page table.
 * @param addr The virtual address to change.
 * @param len The length of the mapping.
 * @param perm The permissions to set.
 */
int vmpl_vm_mprotect(pte_t *root, void *addr, size_t len, int prot)
{
	int ret;
	pte_t pte_perm;

	if (!(prot & PERM_R)) {
		if (prot & PERM_W)
			return -EINVAL;
		prot = PERM_NONE;
	}

	pte_perm = get_pte_perm(prot);
	log_debug(VMPL_VM_MPROTECT_FMT, addr, addr + len - 1, pte_perm);
	ret = __vmpl_vm_page_walk(root, addr, addr + len - 1,
							  &__vmpl_vm_mprotect_helper, (void *)pte_perm,
							  3, CREATE_NONE);
	if (ret)
		return ret;

	vmpl_flush_tlb();

	return 0;
}

/**
 * @brief Clone a page table.
 * @note  This function is not implemented.
 * @param root The root of the page table.
 * @return The new page table root on success, NULL on failure.
 */
pte_t *vmpl_vm_clone(pte_t *root)
{
	int ret;
	pte_t *newRoot;

	log_debug("root = 0x%lx", root);
	newRoot = alloc_virt_page();
	log_debug("newRoot = 0x%lx", newRoot);
	memset(newRoot, 0, PGSIZE);

	log_debug("newRoot = 0x%lx", newRoot);
	// for each vma, walk the page table and clone the pages
	dict_itor *itor = dict_itor_new(vmpl_mm.vmpl_vm.vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		log_debug(VMPL_VM_CLONE_FMT, vma->start, vma->end, vma->prot, vma->path);
		ret = __vmpl_vm_page_walk(root, vma->start, vma->end,
								&__vmpl_vm_clone_helper, newRoot,
								3, CREATE_NONE);
		if (ret < 0) {
			goto failed;
		}
	}

	return newRoot;
failed:
	vmpl_vm_free(newRoot);
	return NULL;
}

/**
 * Free the page table and decrement the reference count on any pages.
 * @param root The root of the page table.
 */
void vmpl_vm_free(pte_t *root)
{
	log_debug("root = 0x%lx", root);
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
}

/**
 * @brief Handle page fault on heap virtual memory area.
 * @param vm The vmpl_vm_t structure to search.
 * @param addr The virtual address to search for.
 * @param len The length of the virtual address range to search for.
 * @return A pointer to the VMA that contains the given virtual address, or NULL
 */
long handle_heap_fault(uintptr_t addr, uint64_t fec, pte_t *pte)
{
	// Allocate a new page
	void *newPage = alloc_virt_page();
	if (!newPage) {
		log_err("alloc_virt_page");
		return -1;
	}

	// Map the new page
	physaddr_t pa = pgtable_va_to_pa(newPage);
	*pte = PTE_ADDR(pa) | PTE_W | PTE_U | PTE_P;

	// Invalidate
	vmpl_flush_tlb_one(addr);
	return 0;
}

/**
 * @brief Handle page fault on stack virtual memory area.
 * @note This function should be called from the page fault handler.
 * @param addr The address that caused the page fault.
 * @param fec The fault error code.
 * @param pte The page table entry to set.
 * @return 0 on success, non-zero on failure.
 */
long handle_stack_fault(uintptr_t addr, uint64_t fec, pte_t *pte)
{
	// Allocate a new page
	void *newPage = alloc_virt_page();
	if (!newPage) {
		log_err("alloc_virt_page");
		return -1;
	}

	// Map the new page
	physaddr_t pa = pgtable_va_to_pa(newPage);
	*pte = PTE_ADDR(pa) | PTE_W | PTE_U | PTE_P;

	// Invalidate
	vmpl_flush_tlb_one(addr);
	return 0;
}

/**
 * @brief Handle page fault on lazily allocated virtual memory area.
 * @note This function should be called from the page fault handler.
 * @param addr The address that caused the page fault.
 * @param fec The fault error code.
 * @return 0 on success, non-zero on failure.
 */
long handle_anonymous_fault(uintptr_t addr, uint64_t fec, pte_t *pte)
{
	// Allocate a new page
	void *newPage = alloc_virt_page();
	if (!newPage) {
		log_err("alloc_virt_page");
		return -1;
	}

	// Map the new page
	physaddr_t pa = pgtable_va_to_pa(newPage);
	*pte = PTE_ADDR(pa) | PTE_W | PTE_U | PTE_P;

	// Invalidate
	vmpl_flush_tlb_one(addr);
	return 0;
}

/**
 * Handle a page fault.
 * This function should be called from the page fault handler.
 * @param addr The address that caused the page fault.
 * @param fec The fault error code.
 * @return 0 on success, non-zero on failure.
 */
long handle_cow_pgflt(uintptr_t addr, uint64_t fec, pte_t *pte)
{
	int rc;

	/*
	 * Assert on present and reserved bits.
	 */
	assert(!(fec & (FEC_P | FEC_RSV)));
	if ((fec & FEC_W) && (*pte & PTE_COW)) {
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
		void *newPage = alloc_virt_page();
		memcpy(newPage, (void *)PGADDR(addr), PGSIZE);

		// Decrement ref count on old page
		vmpl_page_put_addr(PTE_ADDR(*pte));

		// Map page
		physaddr_t pa = pgtable_va_to_pa(newPage);
		*pte = PTE_ADDR(pa) | perm;

		// Invalidate
		vmpl_flush_tlb_one(addr);

		return 0;
	}

	return -1;
}

#ifdef CONFIG_VMPL_MM
/**
 * Handle a page fault.
 * This function should be called from the page fault handler.
 * @param addr The address that caused the page fault.
 * @param fec The fault error code.
 * @return 0 on success, non-zero on failure.
 */
long vmpl_mm_default_pgflt_handler(uintptr_t addr, uint64_t fec)
{
	int rc;
	struct vmpl_vma_t *vma = NULL;
	pte_t *pte = NULL;

	// Find the VMA that contains the faulting address 
	log_debug("addr = 0x%lx, fec = 0x%lx", addr, fec);
	vma = find_vma_intersection(&vmpl_mm.vmpl_vm, PAGE_ALIGN_DOWN(addr), PAGE_SIZE);
	if (!vma) {
		return -1;
	}
	
	// Find the page table entry for the faulting address
	rc = pgtable_lookup(vmpl_mm.pgd, (void *)addr, false, &pte);
	if (rc != 0) {
		return -1;
	}

	log_debug("addr = 0x%lx, fec = 0x%lx, pte = 0x%lx", addr, fec, *pte);
	// Check if the VMA is a heap VMA
	if (vma->flags & VMPL_VMA_TYPE_HEAP) {
		rc = handle_heap_fault(addr, fec, pte);
	} else if (vma->flags & VMPL_VMA_TYPE_STACK) {
		rc = handle_stack_fault(addr, fec, pte);
	} else if (vma->flags & VMPL_VMA_TYPE_ANONYMOUS) {
		rc = handle_anonymous_fault(addr, fec, pte);
	} else {
		rc = handle_cow_pgflt(addr, fec, pte);
	}

	return rc;
}
#else
long vmpl_mm_default_pgflt_handler(uintptr_t addr, uint64_t fec)
{
	log_warn("Unhandled page fault: addr = 0x%lx, fec = 0x%lx", addr, fec);
	return -1;
}
#endif

struct vmpl_mm_t vmpl_mm;

/**
 * @brief Initialize the VMPL Memory Management. 
 * @note This function should be called before any other vmpl_mm_* functions.
 * @param vmpl_mm The vmpl_mm_t structure to initialize.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_mm_init(struct vmpl_mm_t *vmpl_mm)
{
    int rc;

    // VMPL Page Management
    rc = page_init(dune_fd);
    assert(rc == 0);

	// VMPL-VM Abstraction
	rc = vmpl_vm_init(&vmpl_mm->vmpl_vm);
	assert(rc == 0);

	// VMPL Page Table Management
    rc = pgtable_init(&vmpl_mm->pgd, dune_fd);
	assert(rc == 0);

	return 0;
}

/**
 * @brief Exit the VMPL Memory Management.
 * @note This function should be called after any other vmpl_mm_* functions.
 * @param vmpl_mm The vmpl_mm_t structure to exit.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_mm_exit(struct vmpl_mm_t *vmpl_mm)
{
	int rc;
	rc = vmpl_vm_exit(&vmpl_mm->vmpl_vm);
	assert(rc == 0);

	rc = pgtable_exit(vmpl_mm->pgd);
	assert(rc == 0);

	rc = page_exit();
	assert(rc == 0);

	return 0;
}

/**
 * @brief Print the VMPL Memory Management.
 * @note This function should be called after any other vmpl_mm_* functions.
 * @param vmpl_mm The vmpl_mm_t structure to print.
 * @return 0 on success, non-zero on failure.
 */
void vmpl_mm_stats(struct vmpl_mm_t *vmpl_mm)
{
	printf("VMPL Memory Management Stats:\n");
	page_stats();
	pgtable_stats(vmpl_mm->pgd);
	vmpl_vm_stats(&vmpl_mm->vmpl_vm);
}

/**
 * @brief Test the VMPL Memory Management.
 * @note This function should be called after any other vmpl_mm_* functions.
 * @param vmpl_mm The vmpl_mm_t structure to test.
 * @return 0 on success, non-zero on failure.
 */
void vmpl_mm_test(struct vmpl_mm_t *vmpl_mm)
{
	int rc;
	void *addr;
	log_info("VMPL-MM Test");
	page_test(dune_fd);
	pgtable_test(vmpl_mm->pgd, (uint64_t)vmpl_mm->pgd);
	vmpl_vm_test(&vmpl_mm->vmpl_vm);

#ifdef CONFIG_VMPL_MM
	// Test mmap
	log_info("Test mmap");
	addr = vmpl_vm_mmap(&vmpl_mm->pgd, NULL, PGSIZE, PERM_R | PERM_W, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(addr == MAP_FAILED);
	log_success("Test mmap passed");

	// Test mprotect
	log_info("Test mprotect");
	rc = vmpl_vm_mprotect(&vmpl_mm->pgd, addr, PGSIZE, PERM_R);
	assert(rc == 0);
	log_success("Test mprotect passed");

	// Test mremap
	log_info("Test mremap");
	addr = vmpl_vm_mremap(&vmpl_mm->pgd, addr, PGSIZE, PGSIZE * 2, 0, NULL);
	assert(addr == MAP_FAILED);
	log_success("Test mremap passed");

	// Test munmap
	log_info("Test munmap");
	rc = vmpl_vm_munmap(&vmpl_mm->pgd, addr, PGSIZE * 2);
	assert(rc == 0);
	log_success("Test munmap passed");
#endif

	log_success("VMPL-MM Test Passed");
}