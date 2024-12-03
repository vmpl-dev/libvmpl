#define _GNU_SOURCE
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
#include <stdarg.h>
#include <errno.h>
#include <sys/mman.h>
#include <asm/vsyscall.h>

#include "sys.h"
#include "mmu.h"
#include "ioctl.h"
#include "page.h"
#include "vma.h"
#include "vm.h"
#include "mm.h"
#include "log.h"
#include "layout.h"

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

	return pte_perm | PTE_VMPL | PTE_C;
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
	struct page *pg;
	physaddr_t pa;

	pg = vmpl_page_alloc();
	if (!pg)
		return NULL;

	pa = vmpl_page2pa(pg);
	log_debug("pg = 0x%lx, pa = 0x%lx", pg, pa);
	return pa;
}

static inline void free_phys_page(physaddr_t pa)
{
	struct page *pg = vmpl_pa2page(pa);
	vmpl_page_put(pg);
}

static inline virtaddr_t alloc_virt_page(void)
{
	struct page *pg;
	physaddr_t pa;
	virtaddr_t va;

	pg = dune_page_alloc();
	if (!pg)
		return NULL;
	
	pa = dune_page2pa(pg);
	va = pgtable_pa_to_va(pa);
	log_debug("pg = 0x%lx, pa = 0x%lx, va = 0x%lx", pg, pa, va);
	return va;
}

static inline void free_virt_page(virtaddr_t va)
{
	struct page *pg = vmpl_va2page(va);
	dune_page_put(pg);
}

static inline virtaddr_t alloc_zero_page(void)
{
	virtaddr_t va = alloc_virt_page();
	if (va != NULL) {
		memset(va, 0, PGSIZE);
	}

	return va;
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
	void *base_va = (void *)((unsigned long)start_va & ~(PDADDR(level + 1, 1) - 1));

	assert(level >= 0 && level <= NPTLVLS);
	assert(end_idx < NPTENTRIES);

	for (i = start_idx; i <= end_idx; i++) {
		void *n_start_va, *n_end_va;
		void *cur_va = base_va + PDADDR(level, i);
		pte_t *pte = &dir[i];

		if (level == 0) {
			if (create == CREATE_NORMAL || *pte) {
				ret = cb(arg, pte, cur_va);
				if (ret)
					return ret;
			}
			continue;
		}

		if (level == 1) {
			if (create == CREATE_BIG || pte_big(*pte)) {
				ret = cb(arg, pte, cur_va);
				if (ret)
					return ret;
				continue;
			}
		}

		if (level == 2) {
			if (create == CREATE_BIG_1GB || pte_big(*pte)) {
				ret = cb(arg, pte, cur_va);
				if (ret)
					return ret;
				continue;
			}
		}

		if (!pte_present(*pte)) {
			if (!create)
				continue;

			new_dir = alloc_zero_page();
			if (!new_dir)
				return -ENOMEM;
			log_debug("new_dir = 0x%lx, pte = 0x%lx, cur_va = 0x%lx, level = %d",
					  new_dir, *pte, cur_va, level);
			uint64_t pa = pgtable_va_to_pa(new_dir);
			*pte = pte_addr(pa) | PTE_DEF_FLAGS;
			// Clear the C-bit on the page table entry
			if (level > 1) {
				*pte &= ~PTE_C;
			}
		} else {
			new_dir = pgtable_do_mapping(pte_addr(*pte));
			if (!new_dir)
				return -ENOMEM;
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

	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
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

	log_debug("va = 0x%lx, perm = 0x%lx", va, perm);
	physaddr_t pa = alloc_phys_page();
	if (!pa)
		return -ENOMEM;

	*pte = PTE_ADDR(pa) | perm;

	return 0;
}
static int __vmpl_vm_mmap_helper(const void *arg, pte_t *pte, void *va)
{
	struct vmpl_vma_t *vma = (struct vmpl_vma_t *) arg;
	pte_t perm;

	log_debug("va = 0x%lx, prot = 0x%lx, pte = 0x%lx", va, vma->prot, *pte);
	if (vma->prot & PROT_EXEC)
		perm = PTE_VMPL_FLAGS;
	else
		perm = PTE_VMPL_FLAGS | PTE_NX;

#if 0
	// Support MAP_PRIVATE flags.
	if (vma->flags & MAP_PRIVATE) {
		perm &= ~PTE_W;
		perm |= (PTE_COW | PTE_D);
	}

	// Support MAP_SHARED flags.
	if (vma->flags & MAP_SHARED) {
		perm |= PTE_W;
	}
#endif

	// Support MAP_POPULATE flags.
	if (vma->flags & MAP_POPULATE) {
		log_debug("MAP_POPULATE is set");
		// If the page is already present, purely update the permissions.
		if (pte_present(*pte)) {
			log_debug("Page is already present");
		}

		log_debug("Allocating a physical page, va = 0x%lx", va);
		// Allocate a physical page for the virtual page.
		physaddr_t pa = alloc_phys_page();
		if (!pa)
			return -ENOMEM;

		log_debug("Allocated a physical page, va = 0x%lx, pa = 0x%lx", va, pa);
		// Map the physical page to the virtual page.
		*pte = pte_addr(pa);
		// Set the present bit on the page table entry.
		*pte |= PTE_P;
		// Clear the RSV bit on the page table entry.
		perm &= ~PTE_VMPL;
	} else {
		// Clear the page table entry.
		*pte = 0;
	}

out:
	log_debug("va = 0x%lx, perm = 0x%lx", va, perm);
	*pte |= perm;
	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);

	return 0;
}

/**
 * @brief This is a prologue before redirecting `munmap` to the guest OS.
 * @param arg A pointer to a [struct mremap_arg_t] structure.
 * @param pte The page table entry to set.
 * @param va The virtual address to map.
 * @return 0 on success, non-zero on failure.
 */
static int __vmpl_vm_mremap_helper(const void *arg, pte_t *pte, void *va)
{
	int rc;
	struct mremap_arg_t *mremap_arg = (struct mremap_arg_t *)arg;
	pte_t perm, *old_pte;

	size_t offset = va - mremap_arg->new_address;
	log_debug("va = 0x%lx, offset = 0x%lx", va, offset);
	// These are the pages that are not present in the old mapping.
	if (offset >= mremap_arg->old_size) {
		if (mremap_arg->prot & PROT_EXEC)
			perm = PTE_VMPL_FLAGS;
		else
			perm = PTE_VMPL_FLAGS | PTE_NX;
		// Simply popluate the new page table entry.
		log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
		*pte |= perm;
		log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
		return 0;
	}

	// These are the pages that are present in the old mapping.
	rc = pgtable_lookup(mremap_arg->root, mremap_arg->old_address + offset, false, &old_pte);
	if (rc != 0) {
		log_debug("pgtable_lookup failed for va = 0x%lx", mremap_arg->old_address + offset);
		return MAP_FAILED;
	}

	// Copy the old page table entry to the new one, and invalidate the old one.
	log_debug("va = 0x%lx, pte = 0x%lx, old_pte = 0x%lx", va, *pte, *old_pte);
	*pte = *old_pte;

	// Support MREMAP_DONTUNMAP flags.
	if (mremap_arg->flags & MREMAP_DONTUNMAP) {
		goto out;
	}

	*old_pte = 0;
out:
	log_debug("va = 0x%lx, pte = 0x%lx, old_pte = 0x%lx", va, *pte, *old_pte);

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
	pte_t *new_root = (pte_t *)arg;
	pte_t *new_pte;

	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
	// Create new page table entry for the new page table root
	ret = pgtable_lookup(new_root, va, true, &new_pte);
	if (ret < 0)
		return ret;

	// Refcount the physical page, if present.
	if (pte_present(*pte)) {
		if (pte_addr(*pte) > PGTABLE_MMAP_SIZE) {
			log_warn("addr is too large: 0x%lx, pte = 0x%lx, va = 0x%lx", pte_addr(*pte), *pte, va);
			return 0;
		} else {
			vmpl_page_get_addr(pte_addr(*pte));
		}
	}

	// Copy the page table entry
	log_debug("new_pte = 0x%lx", *new_pte);
	*new_pte = *pte;
	log_debug("new_pte = 0x%lx", *new_pte);

	return 0;
}

static inline __vmpl_vm_munmap_helper(const void *arg, pte_t *pte, void *va)
{
	struct vmpl_vma_t *vma = (struct vmpl_vma_t *) arg;

	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
#ifdef CONFIG_DUNE_DEPRECATED
	// Refcount the physical page
	vmpl_page_put_addr(pte_addr(*pte));
#endif

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
	struct vmpl_vma_t *vma = (struct vmpl_vma_t *) arg;
	pte_t perm;

	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
#ifdef CONFIG_DUNE_DEPRECATED
	// If the page is not present, we can't change the permissions?
	if (!(PTE_FLAGS(*pte) & PTE_P))
		return -ENOMEM;
#endif

	if (vma->prot & PROT_EXEC)
		perm = PTE_P | PTE_W | PTE_U;
	else
		perm = PTE_P | PTE_W | PTE_U | PTE_NX;

	// Clear the present bit on non-present pages
	if (!pte_present(*pte))
		perm &= ~PTE_P;

	*pte = pte_addr(*pte) | (PTE_FLAGS(*pte) & PTE_PS) | perm;

	return 0;
}

/**
 * Change the permissions of a virtual memory page.
 * @param arg A pointer to a pte_t structure.
 * @param pte The page table entry to set.
 * @param va The virtual address to change.
 * @return int 0 on success, non-zero on failure.
 */
static int __vmpl_vm_pkey_mprotect_helper(const void *arg, pte_t *pte, void *va)
{
	pte_t *perm = (pte_t *)arg;

	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
#ifdef CONFIG_DUNE_DEPRECATED
	// If the page is not present, we can't change the permissions?
	if (!(PTE_FLAGS(*pte) & PTE_P))
		return -ENOMEM;
#endif

	// Set the protection key on the page table entry.
	log_debug("va = 0x%lx, perm = 0x%lx", va, *perm);
	*pte |= (*perm);
	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);

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
	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);

#ifdef CONFIG_DUNE_DEPRECATED
	// Free the physical page
	free_phys_page(pte_addr(*pte));
#endif

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
 * @brief Dune VM Page Walk
 * @param root The root of the page table.
 * @param vm The VMPL VM to walk.
 * @param cb The callback function to call for each page.
 * @param arg An argument to pass to the callback function.
 * @param level The level of the page table.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_vm_vma_walk(pte_t *root, struct vmpl_vm_t *vm, page_walk_cb cb, const void *arg, int level)
{
	int ret = 0;
	struct vmpl_vma_t *vma;
	// For each vmpl-vma, walk the page table and call the callback function.
	dict_itor *itor = dict_itor_new(vm->vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		vma = dict_itor_key(itor);
		// Skip the vsyscall page
		if (vma->start == VSYSCALL_ADDR)
			continue;
		log_debug("start = 0x%lx, end = 0x%lx, level = %d, vm_file = %s",
				  vma->start, vma->end, level, vma->vm_file);
		ret = __vmpl_vm_page_walk(root, vma->start, vma->end - 1,
								  cb, arg, level, CREATE_NONE);
		if (ret)
			break;
	}
	dict_itor_free(itor);
	return ret;
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

int vmpl_vm_insert_page(pte_t *root, void *va, struct page *pg, int perm)
{
	return -1;
}

struct page * vmpl_vm_lookup_page(pte_t *root, void *va)
{
	int rc;
	pte_t *ptep;
	rc = pgtable_lookup(root, va, false, &ptep);
	if (rc != 0) {
		return NULL;
	}

	return vmpl_pa2page(pte_addr(*ptep));
}

int vmpl_vm_lookup(pte_t *root, void *va, int create, pte_t **pte_out)
{
	return pgtable_lookup(root, va, create, pte_out);
}

/**
 * @brief Discard all VMAs that intersect with the given range.
 * @note VMPL-VM Low Level API
 * @param vm The VMPL-VM to remove from.
 * @param va_start The start address of the range.
 * @param va_end The end address of the range.
 * @return None.
 */
static int unmap_vma(void *va_start, void *va_end)
{
	int rc;
	struct vmpl_vm_t *vm = &vmpl_mm.vmpl_vm;
	struct vmpl_vma_t *vma;
	bool removed;

	while ((vma = find_vma_intersection(vm, va_start, va_end)) != NULL) {
		// Walk the page table and unmap the pages in the VMA.
		int rc = __vmpl_vm_page_walk(vmpl_mm.pgd, vma->start, vma->end - 1,
									&__vmpl_vm_munmap_helper, vma,
									3, CREATE_NONE);
		if (rc != 0) {
			log_debug("Failed to walk the page table");
			errno = ENOMEM;
			return -1;
		}

		removed = remove_vma(vm, vma);
		assert(removed == true);
		vmpl_vma_free(vma);
	}

	return 0;
}

/**
 * @brief This is a prologue before redirecting `mmap` to the guest OS.
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
	void *va_start, *va_end;
	struct vmpl_vm_t *vm = &vmpl_mm.vmpl_vm;
	struct vmpl_vma_t *vma;
	int rc;

	log_debug(VMPL_VM_MMAP_FMT, addr, addr + length, prot, flags, fd, offset);
	// Filter out unsupported file-backed mappings
	if (fd != -1) {
		log_debug("File-backed mappings are not supported");
		errno = ENOTSUP;
		return MAP_FAILED;
	}

	// Filter out unsupported flags
	if (flags & (MAP_GROWSDOWN | MAP_STACK | MAP_HUGETLB | MAP_LOCKED | MAP_NONBLOCK)) {
		log_debug("Unsupported flags");
		errno = ENOTSUP;
		return MAP_FAILED;
	}

	/* force arch specific MAP_FIXED handling in get_unmapped_area */
	if (flags & MAP_FIXED_NOREPLACE)
		flags |= MAP_FIXED;

	// Check that the address is not NULL
	if (addr != NULL) {
		// Align address and length
		va_start = PAGE_ALIGN_DOWN((uintptr_t)addr);
		va_end = PAGE_ALIGN_UP((uintptr_t)(addr + length));

		// Check that the address range belongs to the VMPL VM
		if (va_end <= vm->va_start || va_start >= vm->va_end) {
			log_debug("The address range does not belong to the VMPL VM");
			errno = ENOMEM;
			return MAP_FAILED;
		}

		// Check that the address range is not already mapped
		vma = find_vma_intersection(vm, va_start, va_end);
		if (vma != NULL) {
			log_debug("The address range is already mapped");

			// Support MAP_FIXED_NOREPLACE (since Linux 4.17)
			if (flags & MAP_FIXED_NOREPLACE) {
				log_debug("MAP_FIXED_NOREPLACE is set");
				errno = EEXIST;
				return MAP_FAILED;
			}

			// If MAP_FIXED is set, discard any overlapping mappings
			if (flags & MAP_FIXED) {
				log_debug("MAP_FIXED is set, discarding overlapping mappings");
				// For fixed mappings, we need to replace any existing mapping at the specified address.
				// Here, we assume that the function unmap_vma is available to unmap any existing VMA.
				rc = unmap_vma(va_start, va_end);
				if (rc != 0) {
					errno = ENOMEM;
					return MAP_FAILED;
				}
			}
		}

		// Allocate new VMA for the new address range
		vma = alloc_vma_range(vm, va_start, length);
		if (vma == NULL) {
			log_debug("Failed to allocate new VMA");
			errno = ENOMEM;
			return MAP_FAILED;
		}
	} else {
		// Find unused virtual memory area
		vma = alloc_vma(vm, length);
		if (vma == NULL) {
			log_debug("Failed to allocate new VMA");
			errno = ENOMEM;
			return MAP_FAILED;
		}
	}

	// Populate the new VMA
	vma->prot = prot;
	vma->flags = flags;
	vma->offset = offset;
	vma->inode	= 0;
	vma->major	= 0;
	vma->minor	= 0;
	vma->vm_file = strdup("[vmpl]");

	// Allocate page table entries for the new VMA
	rc = __vmpl_vm_page_walk(vmpl_mm.pgd, vma->start, vma->end - 1,
							 &__vmpl_vm_mmap_helper, vma,
							 3, CREATE_NORMAL);

	if (rc != 0) {
		log_debug("Failed to walk the page table");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Insert new VMA into VMPL-VM
	bool inserted = insert_vma(vm, vma);
	if (!inserted) {
		log_debug("Failed to insert VMA into VMPL-VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Flush the TLB
	vmpl_flush_tlb();

	// Return the start of the new VMA
	return (void *)vma->start;
}

/**
 * @brief This is a prologue before redirecting `mremap` to the guest OS.
 * @param root The root of the page table.
 * @param old_address The old address, must be a multiple of PGSIZE, and must be
 * a valid address in the VMPL-VM virtual address space.
 * @param old_size The old size, must be a multiple of PGSIZE.
 * @param new_size The new size, must be a multiple of PGSIZE.
 * @param flags The flags to set (MREMAP_MAYMOVE, MREMAP_FIXED, MREMAP_DONTUNMAP).
 * @param new_address The new address, must be a multiple of PGSIZE, and must be
 * in the range of the VMPL-VM virtual address space.
 * @return 0 on success, non-zero on failure.
 */
void *vmpl_vm_mremap(pte_t *root, void *old_address, size_t old_size,
					 size_t new_size, int flags, ... /* void *new_address */)
{
	void *new_address = NULL;
	struct vmpl_vma_t *old_vma, *new_vma;
	struct vmpl_vm_t *vm = &vmpl_mm.vmpl_vm;
	void *ret;
	int rc;

	// Check that the address is not NULL
	if (old_address == NULL) {
		log_debug("old_address is NULL");
		errno = EINVAL;
		return MAP_FAILED;
	}

	// Align old address and size
	old_address = (void *)PAGE_ALIGN_DOWN((uintptr_t)old_address);
	old_size = PAGE_ALIGN_UP(old_size);
	new_size = new_size ? PAGE_ALIGN_UP(new_size) : old_size;

	// Default flags to MREMAP_MAYMOVE
	flags = flags ? flags : MREMAP_MAYMOVE;

	// Check that the old address range is mapped
	old_vma = find_vma_intersection(vm, old_address, old_address + old_size);
	if (old_vma == NULL) {
		log_debug("The old address range is not mapped");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Check that the old address range belongs to the VMPL VM
	if ((old_address + old_size) <= vm->va_start ||
		 old_address >= vm->va_end) {
		log_debug("The old address range does not belong to the VMPL VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Support MREMAP_FIXED (since Linux 2.3.31)
	if (flags & MREMAP_FIXED) {
		// Obtain the new address from the variadic arguments
		va_list ap;
		va_start(ap, flags);
		new_address = va_arg(ap, void *);
		va_end(ap);
	}

	if (new_address != NULL) {
		// Align new address and size (if MREMAP_FIXED is set)
		new_address = (void *)PAGE_ALIGN_DOWN((uintptr_t)new_address);
		log_debug(VMPL_VM_MREMAP_FMT, old_address, old_address + old_size,
				new_address, new_address + new_size, flags);

		// Check that the new address range belongs to the VMPL VM
		if ((new_address + new_size) <= vm->va_start ||
			 new_address >= vm->va_end) {
			log_debug("The new address range does not belong to the VMPL VM");
			errno = ENOMEM;
			return MAP_FAILED;
		}

		// Check that the new address range is not already mapped
		new_vma = find_vma_intersection(vm, new_address, new_address + new_size);
		if (new_vma != NULL) {
			log_debug("The address range is already mapped");

			// If MAP_FIXED is set, discard any overlapping mappings
			if (flags & MREMAP_FIXED) {
				log_debug("MAP_FIXED is set, discarding overlapping mappings");
				// Support MREMAP_FIXED, munmap the overlapping mappings
				rc = unmap_vma(new_address, new_address + new_size);
				if (rc != 0) {
					log_debug("Failed to walk the page table");
					errno = ENOMEM;
					return MAP_FAILED;
				}
			} else {
				errno = EEXIST;
				return MAP_FAILED;
			}
		}

		// Allocate new VMA for the new address range
		new_vma = alloc_vma_range(vm, new_address, new_size);
		if (new_vma == NULL) {
			log_debug("Failed to allocate new VMA");
			errno = ENOMEM;
			return MAP_FAILED;
		}
	} else {
		// Check that there is enough space for expanding the VMA in-place (if MREMAP_FIXED is not set).
		new_vma = find_next_vma(vm, old_vma);
		if (((new_vma == NULL) && (old_address + new_size <= vm->va_end))
			|| ((new_vma != NULL) && (old_address + new_size <= new_vma->start))) {
			// Expand the VMA in-place (if there is enough space)
			old_vma->end = old_address + new_size;
			old_vma->flags = flags;
			log_debug("Expanding VMA in-place, start = 0x%lx, end = 0x%lx",
					  old_vma->start, old_vma->end);
			vmpl_vma_free(new_vma);
			// Allocate page table entries for the new VMA (if MREMAP_FIXED is not set)
			ret = __vmpl_vm_page_walk(vmpl_mm.pgd, old_address + old_size, old_address + new_size - 1,
									  &__vmpl_vm_mremap_helper, old_vma,
									  3, CREATE_NORMAL);
			return old_address;
		} else {
			// Allocate new VMA for the new address range
			new_vma = alloc_vma(vm, new_size);
			if (new_vma == NULL) {
				log_debug("Failed to allocate new VMA");
				errno = ENOMEM;
				return MAP_FAILED;
			}
		}

		new_address = (void *)new_vma->start;
	}

	log_debug(VMPL_VM_MREMAP_FMT, old_address, old_address + old_size,
			new_address, new_address + new_size, flags);

	// Populate the new VMA
	struct mremap_arg_t mremap_arg = {
		.prot = old_vma->prot,
		.flags = flags,
		.new_address = new_address,
		.new_size = new_size,
		.old_address = old_address,
		.old_size = old_size,
		.root = root,
	};

	// Allocate page table entries for the new VMA
	ret = __vmpl_vm_page_walk(vmpl_mm.pgd, new_address, new_address + new_size - 1,
						&__vmpl_vm_mremap_helper, &mremap_arg,
						3, CREATE_NORMAL);

	// Remove old VMA from VMPL-VM, and insert new VMA into VMPL-VM
	if (ret != 0) {
		log_debug("Failed to walk the page table");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Copy the old VMA to the new VMA
	new_vma->flags = flags;
	new_vma->prot = old_vma->prot;
	new_vma->offset = old_vma->offset;
	new_vma->major = old_vma->major;
	new_vma->minor = old_vma->minor;
	new_vma->inode = old_vma->inode;
	new_vma->vm_file = strdup(old_vma->vm_file);

	// Insert new VMA into VMPL-VM
	bool inserted = insert_vma(vm, new_vma);
	if (!inserted) {
		log_debug("Failed to insert VMA into VMPL-VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Support MREMAP_DONTUNMAP flags.
	if (flags & MREMAP_DONTUNMAP) {
		goto out;
	}

	// Unmap the old VMA
	rc = __vmpl_vm_page_walk(vmpl_mm.pgd, old_address, old_address + old_size - 1,
							 &__vmpl_vm_munmap_helper, old_vma,
							 3, CREATE_NONE);
	if (rc != 0) {
		log_debug("Failed to walk the page table");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Remove old VMA from VMPL-VM
	bool removed = remove_vma(vm, old_vma);
	if (!removed) {
		log_debug("Failed to remove VMA from VMPL-VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	vmpl_vma_free(old_vma);

out:
	vmpl_flush_tlb();
	return (void *)new_vma->start;
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
	int ret;
	void *va_start, *va_end;
	struct vmpl_vma_t *vma;
	struct vmpl_vm_t *vm = &vmpl_mm.vmpl_vm;

	// Check that the address is not NULL
	if (addr == NULL) {
		log_debug("addr is NULL");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Align address and length
	va_start = (void *)PAGE_ALIGN_DOWN((uintptr_t)addr);
	va_end = (void *)PAGE_ALIGN_UP((uintptr_t)addr + length);
	log_debug(VMPL_VM_MUNMAP_FMT, va_start, va_end);

	// Check that the address range belongs to the VMPL VM
	if (va_end <= vm->va_start || va_start >= vm->va_end) {
		log_debug("The address range does not belong to the VMPL VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Check that the address range is mapped
	vma = find_vma_intersection(vm, va_start, va_end);
	if (vma == NULL) {
		log_debug("The address range is not mapped");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	/* FIXME: Doesn't free as much memory as it could */
	ret = __vmpl_vm_page_walk(root, va_start, va_end - 1,
						&__vmpl_vm_free_helper, vma,
						3, CREATE_NONE);

	if (ret != 0) {
		log_debug("Failed to walk the page table");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Remove VMA from VMPL-VM
	bool removed = remove_vma(vm, vma);
	if (!removed) {
		log_debug("Failed to remove VMA from VMPL-VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	vmpl_vma_free(vma);

	// Flush TLB Entries
	vmpl_flush_tlb();

	return ret;
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
	void *va_start, *va_end;
	struct vmpl_vma_t *vma;
	struct vmpl_vm_t *vm = &vmpl_mm.vmpl_vm;

	// Check permissions are valid (must have at least one of R, W, X)
	if (!(prot & PROT_READ)) {
		if (prot & PROT_WRITE) {
			errno = EINVAL;
			return MAP_FAILED;
		}
		prot = PROT_NONE;
	}

	// Check that the address is not NULL
	if (addr == NULL) {
		log_debug("addr is NULL");
		errno = EINVAL;
		return MAP_FAILED;
	}

	// EINVAL addr is not a valid pointer, or not a multiple of the system page size.
	if ((uintptr_t)addr % PGSIZE) {
		log_debug("addr is not a multiple of the system page size");
		errno = EINVAL;
		return MAP_FAILED;
	}

	// EINVAL Both PROT_GROWSUP and PROT_GROWSDOWN were specified in prot.
	if (prot & (PROT_GROWSUP | PROT_GROWSDOWN)) {
		log_debug("PROT_GROWSUP and PROT_GROWSDOWN are not supported");
		errno = ENOTSUP;
		return MAP_FAILED;
	}

	// EINVAL Invalid flags specified in prot.
	if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_NONE | PROT_GROWSUP | PROT_GROWSDOWN)) {
		log_debug("Invalid flags specified in prot");
		errno = EINVAL;
		return MAP_FAILED;
	}

	// Align address and length
	va_start = (void *)PAGE_ALIGN_DOWN((uintptr_t)addr);
	va_end = (void *)PAGE_ALIGN_UP((uintptr_t)addr + len);
	log_debug(VMPL_VM_MPROTECT_FMT, va_start, va_end, prot);

	// Check that the address range belongs to the VMPL VM
	if (va_end <= vm->va_start || va_start >= vm->va_end) {
		log_debug("The address range does not belong to the VMPL VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Check that the address range is mapped
	vma = find_vma_intersection(vm, va_start, va_end);
	if (vma == NULL) {
		log_debug("The address range is not mapped");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	log_debug(VMPL_VM_MPROTECT_FMT, va_start, va_end, vma->prot);
	vma->prot = prot;
	log_debug(VMPL_VM_MPROTECT_FMT, va_start, va_end, vma->prot);

	ret = __vmpl_vm_page_walk(root, va_start, va_end - 1,
							  &__vmpl_vm_mprotect_helper, (void *)vma,
							  3, CREATE_NONE);
	if (ret) {
		log_debug("Failed to walk the page table");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	vmpl_flush_tlb();

	return 0;
}

/**
 * @brief Change the permissions of virtual memory pages.
 * @note Note: len must be a multiple of PGSIZE.
 * @param root The root of the page table.
 * @param addr The virtual address to change.
 * @param len The length of the mapping.
 * @param prot The permissions to set.
 * @param pkey The protection key to set.
 * @return int 0 on success, non-zero on failure.
 */
int vmpl_vm_pkey_mprotect(pte_t *root, void *addr, size_t len, int prot, int pkey)
{
	int ret = 0;
	void *va_start, *va_end;
	pte_t perm;

	// Perform the same checks as vmpl_vm_mprotect
	ret = vmpl_vm_mprotect(root, addr, len, prot);
	if (ret) {
		log_debug("vmpl_vm_mprotect failed");
		return ret;
	}

	// Check that the protection key is valid
	if (pkey < 0 || pkey >= 16) {
		log_debug("Invalid protection key");
		errno = EINVAL;
		return MAP_FAILED;
	}

	// Align address and length
	va_start = (void *)PAGE_ALIGN_DOWN((uintptr_t)addr);
	va_end = (void *)PAGE_ALIGN_UP((uintptr_t)addr + len);
	perm = pkey << PTE_PKEY_SHIFT;

	// Call the pkey_mprotect_helper for each page in the range [addr, addr + len)
	log_debug(VMPL_VM_PKEY_MPROTECT_FMT, va_start, va_end, prot, pkey);
	ret = __vmpl_vm_page_walk(root, va_start, va_end - 1,
							  &__vmpl_vm_pkey_mprotect_helper, (void *)&perm,
							  3, CREATE_NONE);
	if (ret) {
		log_debug("Failed to walk the page table");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Flush TLB Entries
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
	pte_t *new_root;

	new_root = alloc_zero_page();
	log_debug("root = %lx, new_root = %lx", root, new_root);

	ret = __vmpl_vm_page_walk(root, VA_START, VA_END,
							&__vmpl_vm_clone_helper, new_root,
							3, CREATE_NONE);
	if (ret < 0) {
		vmpl_vm_free(new_root);
		return NULL;
	}

	return new_root;
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
 * Handle a page fault.
 * This function should be called from the page fault handler.
 * @param addr The address that caused the page fault.
 * @param fec The fault error code.
 * @return 0 on success, non-zero on failure.
 */
long dune_vm_default_pgflt_handler(uintptr_t addr, uint64_t fec)
{
	pte_t *pte = NULL;
	int rc;

	rc = vmpl_vm_lookup(pgroot, (void *)addr, 0, &pte);
	if (rc != 0)
		return rc;

	if ((fec & FEC_W) && is_cow_page(*pte)) {
		physaddr_t pa = pte_addr(*pte);
		struct page *pg = vmpl_pa2page(pa);
		pte_t perm = pte_flags(*pte);

		// Compute new permissions
		perm &= ~PTE_COW;
		perm |= PTE_W;

		// Check if we can just change permissions
		if (vmpl_page_is_from_pool(pa) && pg->ref == 1) {
			*pte = pa | perm;
			return 0;
		}

		// Duplicate page
		void *new_page = alloc_virt_page();
		memcpy(new_page, (void *)PGADDR(addr), PGSIZE);

		// Decrement ref count on old page
		vmpl_page_put_addr(pa);

		// Map page
		pa = pgtable_va_to_pa(new_page);
		*pte = pte_addr(pa) | perm;

		// Invalidate
		vmpl_flush_tlb_one(addr);

		return 0;
	}

	return -1;
}

/**
 * Handle a page fault.
 * This function should be called from the page fault handler.
 * @param addr The address that caused the page fault.
 * @param fec The fault error code.
 * @return 0 on success, non-zero on failure.
 */
long vmpl_mm_default_pgflt_handler(uintptr_t addr, uint64_t fec)
{
	struct vmpl_vm_t *vmpl_vm = &vmpl_mm.vmpl_vm;
	void *va_start, *va_end;
	pte_t *pte;
	int rc;
	pte_t perm;

	// Align address
	va_start = (void *)PAGE_ALIGN_DOWN(addr);
	va_end = (void *)PAGE_ALIGN_UP(addr + PAGE_SIZE);

	if (va_start < vmpl_vm->va_start || va_start >= vmpl_vm->va_end) {
		return -ENOENT;
	}

	// Find the page table entry for the faulting address
	rc = vmpl_vm_lookup(pgroot, (void *)va_start, false, &pte);
	if (rc != 0)
		return rc;

	// Check if the page belongs to vmpl-mm.
	if (!pte_vmpl(*pte)) {
		return -ENOENT;
	}

	// Check if the page is already allocated.
	if (pte_present(*pte)) {
		return -EEXIST;
	}

	// Allocate a new page
	phys_addr_t pa = alloc_phys_page();
	if (pa == NULL) {
		return -ENOMEM;
	}

	perm = pte_flags(*pte);
	perm |= (PTE_P | PTE_C);
	perm &= ~PTE_VMPL;

	// Map the new page
	*pte = pte_addr(pa) | perm;

	// Invalidate TLB
	vmpl_flush_tlb_one(addr);

	return 0;
}

struct vmpl_mm_t vmpl_mm = {
	.initialized = false,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

/**
 * @brief Initialize the VMPL Memory Management. 
 * @note This function should be called before any other vmpl_mm_* functions.
 * @param vmpl_mm The vmpl_mm_t structure to initialize.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_mm_init(struct vmpl_mm_t *vmpl_mm)
{
    int rc = 0;

	pthread_mutex_lock(&vmpl_mm->lock);

	// VMPL Memory Management
	if (vmpl_mm->initialized) {
		goto out;
	}

	// 初始化地址转换策略
	rc = mapping_init(false);
	if (rc != 0) {
		log_err("Failed to initialize address mapping");
		goto out;
	}

    // VMPL Page Management
    rc = vmpl_page_init();
	if (rc != 0) {
		log_err("Failed to initialize page management");
		goto out;
	}

	// VMPL-VM Abstraction
	rc = vmpl_vm_init(&vmpl_mm->vmpl_vm);
	if (rc != 0) {
		log_err("Failed to initialize VMPL-VM");
		goto out;
	}

	// VMPL Page Table Management
    rc = pgtable_init(&vmpl_mm->pgd, dune_fd);
	if (rc != 0) {
		log_err("Failed to initialize page table");
		goto out;
	}

	// VMPL Memory Management
	rc = vmpl_vm_init_procmaps(&vmpl_mm->vmpl_vm);
	if (rc != 0) {
		log_err("Failed to initialize VMPL-VM procmaps");
		goto out;
	}

	vmpl_mm->initialized = true;
out:
	pthread_mutex_unlock(&vmpl_mm->lock);

	return rc;
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

	rc = vmpl_page_exit();
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

#ifdef CONFIG_VMPL_TEST
void vmpl_mm_test_mmap(struct vmpl_mm_t *vmpl_mm)
{
	int rc;
	void *addr, *tmp_addr;
	pte_t *ptep;
	pte_t *new_root;
	struct vmpl_vma_t *vma;
	struct vmpl_vm_t *vm = &vmpl_mm->vmpl_vm;

#if 0
	// Test page table entry lookup
	log_info("Test page table entry lookup");
	rc = pgtable_lookup(vmpl_mm->pgd, vmpl_mm->vmpl_vm.va_start, false, &ptep);
	assert(rc == 0);
	assert(ptep != NULL);
	log_success("Test page table entry lookup passed, pte = 0x%lx", *ptep);
#endif

	// Test mmap
	log_info("Test mmap");
	addr = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	assert(addr != MAP_FAILED);
	assert(addr == vmpl_mm->vmpl_vm.va_start);
	vma = find_vma_intersection(vm, addr, addr + PGSIZE);
	assert(vma != NULL);
	assert(vma->prot == (PROT_READ | PROT_WRITE));
	assert(vma->flags == (MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE));
	assert(vma->end - vma->start == PGSIZE);
	log_success("Test mmap passed");

	// Test page table entry lookup
	log_info("Test page table entry lookup");
	rc = pgtable_lookup(vmpl_mm->pgd, addr, false, &ptep);
	assert(rc == 0);
	assert(ptep != NULL);
	log_success("Test page table entry lookup passed, pte = 0x%lx", *ptep);

	// Test access to the mapped page
	log_info("Test access to the mapped page");
	*(uint64_t *)(addr) = 0xdeadbeef;
	assert(*(uint64_t *)addr == 0xdeadbeef);
	log_success("Test access to the mapped page passed");

	// Test mmap at a specific address
	log_info("Test mmap at a specific address");
	tmp_addr = (void *)vmpl_mm->vmpl_vm.va_start + PGSIZE;
	addr = mmap(tmp_addr, PGSIZE, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	assert(addr != MAP_FAILED);
	assert(addr == tmp_addr);
	log_success("Test mmap at a specific address passed");

	// Test access to the mapped page at a specific address
	pgtable_lookup(vmpl_mm->pgd, addr, false, &ptep);
	log_info("Test access to the mapped page at a specific address, pte = 0x%lx", *ptep);
	assert(!pte_present(*ptep));
	*(uint64_t *)(addr) = 0xdeadbeef;
	assert(*(uint64_t *)addr == 0xdeadbeef);
	assert(pte_present(*ptep));
	log_success("Test access to the mapped page at a specific address passed");

	// Test mmap at a specific address that is already mapped with MAP_FIXED_NOREPLACE.
	log_info("Test mmap at a specific address that is already mapped with MAP_FIXED_NOREPLACE");
	addr = mmap(tmp_addr, PGSIZE, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	assert(addr == MAP_FAILED);
	assert(errno == EEXIST);
	log_success("Test mmap at a specific address that is already mapped with MAP_FIXED_NOREPLACE passed");

	// Test mmap at a specific address that is already mapped with MAP_FIXED.
	log_info("Test mmap at a specific address that is already mapped with MAP_FIXED");
	addr = mmap(tmp_addr, PGSIZE, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	assert(addr != MAP_FAILED);
	assert(addr == tmp_addr);
	log_success("Test mmap at a specific address that is already mapped with MAP_FIXED passed");

	// Test mprotect
	log_info("Test mprotect");
	rc = mprotect(addr, PGSIZE, PROT_READ);
	assert(rc == 0);
	vma = find_vma_intersection(vm, addr, addr + PGSIZE);
	assert(vma != NULL);
	assert(vma->prot == PROT_READ);
	log_success("Test mprotect passed");

	// Test pkey_alloc
	log_info("Test pkey_alloc");
	int pkey = pkey_alloc(0, PKEY_DISABLE_WRITE);
	assert(pkey >= 0);
	log_success("Test pkey_alloc passed");

	// Test pkey_free
	log_info("Test pkey_free");
	rc = pkey_free(pkey);
	assert(rc == 0);
	log_success("Test pkey_free passed");

	// Test pkey_mprotect
	log_info("Test pkey_mprotect");
	pkey = pkey_alloc(0, PKEY_DISABLE_WRITE);
	rc = pkey_mprotect(addr, PGSIZE, PROT_READ, pkey);
	assert(rc == 0);
	vma = find_vma_intersection(vm, addr, addr + PGSIZE);
	assert(vma != NULL);
	assert(vma->prot == PROT_READ);
	log_success("Test pkey_mprotect passed");

	// Test mremap
	log_info("Test mremap");
	addr = mremap(addr, PGSIZE, PGSIZE * 2, MREMAP_MAYMOVE, NULL);
	assert(addr != MAP_FAILED);
	vma = find_vma_intersection(vm, addr, addr + PGSIZE * 2);
	assert(vma != NULL);
	assert(vma->prot == PROT_READ);
	assert(vma->flags == MREMAP_MAYMOVE);
	assert(vma->end - vma->start == PGSIZE * 2);
	log_success("Test mremap passed");

	// Test mremap to a specific address with MREMAP_FIXED | MREMAP_DONTUNMAP.
	log_info("Test mremap to a specific address with MREMAP_FIXED | MREMAP_DONTUNMAP");
	tmp_addr = (void *)vmpl_mm->vmpl_vm.va_start + PGSIZE * 8;
	addr = mremap(addr, PGSIZE * 2, PGSIZE * 2,
						  MREMAP_FIXED | MREMAP_DONTUNMAP, tmp_addr);
	assert(addr != MAP_FAILED);
	assert(addr == tmp_addr);
	vma = find_vma_intersection(vm, tmp_addr, tmp_addr + PGSIZE * 2);
	assert(vma->prot == PROT_READ);
	assert(vma->flags == MREMAP_FIXED | MREMAP_DONTUNMAP);
	log_success("Test mremap to a specific address with MREMAP_FIXED | MREMAP_DONTUNMAP passed");

	// Test munmap
	log_info("Test munmap");
	rc = munmap(addr, PGSIZE * 2);
	assert(rc == 0);
	vma = find_vma_intersection(vm, addr, addr + PGSIZE * 2);
	assert(vma == NULL);
	log_success("Test munmap passed");

	// Test clone
	log_info("Test clone");
	new_root = vmpl_vm_clone(vmpl_mm->pgd);
	assert(new_root != NULL);
	log_success("Test clone passed");

	// Test load new page table
	log_info("Test load new page table");
	load_cr3(CR3_NOFLUSH | (uint64_t)new_root | 1);
	log_success("Test load new page table passed");

	// Restore the original page table
	load_cr3(CR3_NOFLUSH | (uint64_t)vmpl_mm->pgd);

	// Test free
	log_info("Test free");
	vmpl_vm_free(new_root);
	log_success("Test free passed");
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
	vmpl_mm_test_mmap(vmpl_mm);
	log_success("VMPL-MM Test Passed");
}
#endif

int setup_mm()
{
    int rc;
    log_info("setup mm");

    rc = mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT);
    if (rc != 0) {
        log_err("dune: %s", strerror(errno));
        goto failed;
    }

    rc = vmpl_mm_init(&vmpl_mm);
    if (rc != 0) {
        log_err("dune: unable to setup vmpl mm");
        goto failed;
    }

    return 0;
failed:
    return rc;
}