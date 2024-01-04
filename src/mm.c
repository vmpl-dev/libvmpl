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

			new_dir = alloc_virt_page();
			if (!new_dir)
				return -ENOMEM;
			log_debug("new_dir = 0x%lx, pte = 0x%lx, cur_va = 0x%lx, level = %d",
					  new_dir, *pte, cur_va, level);
			memset(new_dir, 0, PGSIZE);
			uint64_t pa = pgtable_va_to_pa(new_dir);
			*pte = pte_addr(pa) | PTE_DEF_FLAGS | PTE_C;
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
		perm = PTE_P | PTE_W | PTE_U | PTE_C;
	else
		perm = PTE_P | PTE_W | PTE_U | PTE_C | PTE_NX;

	log_debug("va = 0x%lx, perm = 0x%lx", va, perm);
	*pte |= perm;
	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);

	return 0;
}

/**
 * @brief This is a prologure before redirecting `munmap` to the guest OS.
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
		// Simply popluate the new page table entry.
		log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
		*pte = PTE_DEF_FLAGS & ~PTE_P;
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
	*old_pte = 0;
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
	pte_t *newRoot = (pte_t *)arg;
	pte_t *newPte;

	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
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
	struct vmpl_vma_t *vma = (struct vmpl_vma_t *) arg;

	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);
	// Refcount the physical page
	vmpl_page_put_addr(pte_addr(*pte));

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
	log_debug("va = 0x%lx, pte = 0x%lx", va, *pte);

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
	void *va_start, *va_end;
	struct vmpl_vm_t *vm = &vmpl_mm.vmpl_vm;
	struct vmpl_vma_t *vma;
	int rc;

	log_debug(VMPL_VM_MMAP_FMT, addr, addr + length, prot, flags, fd, offset);
	// Filter out unsupported file-backed mappings
	if (fd != -1) {
		log_warn("File-backed mappings are not supported");
		errno = ENOTSUP;
		return MAP_FAILED;
	}

	// Filter out unsupported flags
	if (flags & (MAP_SHARED | MAP_FIXED | MAP_GROWSDOWN | MAP_STACK | MAP_HUGETLB)) {
		log_warn("Unsupported flags");
		errno = ENOTSUP;
		return MAP_FAILED;
	}

	// Check that the address is not NULL
	if (addr != NULL) {
		// Align address and length
	 	va_start = PAGE_ALIGN_DOWN((uintptr_t)addr);
		va_end = PAGE_ALIGN_UP((uintptr_t)(addr + length));

		// Check that the address range belongs to the VMPL VM
		if (va_end <= vm->va_start || va_start >= vm->va_end) {
			log_warn("The address range does not belong to the VMPL VM");
			errno = ENOMEM;
			return MAP_FAILED;
		}

		// Check that the address range is not already mapped
		vma = find_vma_intersection(vm, va_start, va_end);
		if (vma != NULL) {
			log_warn("The address range is already mapped");
			errno = EEXIST;
			return MAP_FAILED;
		}

		// Allocate new VMA for the new address range
		vma = alloc_vma_range(vm, va_start, length);
		if (vma == NULL) {
			log_warn("Failed to allocate new VMA");
			errno = ENOMEM;
			return MAP_FAILED;
		}
	} else {
		// Find unused virtual memory area
		vma = alloc_vma(vm, length);
		if (vma == NULL) {
			log_warn("Failed to allocate new VMA");
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
	vma->path = strdup("anon");

	// Allocate page table entries for the new VMA
	rc = __vmpl_vm_page_walk(vmpl_mm.pgd, vma->start, vma->end - 1,
							 &__vmpl_vm_mmap_helper, vma,
							 3, CREATE_NORMAL);

	if (rc != 0) {
		log_warn("Failed to walk the page table");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Insert new VMA into VMPL-VM
	bool inserted = insert_vma(vm, vma);
	if (!inserted) {
		log_warn("Failed to insert VMA into VMPL-VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	return (void *)vma->start;
}

/**
 * @brief This is a prologure before redirecting `mremap` to the guest OS.
 * @param root The root of the page table.
 * @param old_address The old address, must be a multiple of PGSIZE, and must be
 * a valid address in the VMPL-VM virtual address space.
 * @param old_size The old size, must be a multiple of PGSIZE.
 * @param new_size The new size, must be a multiple of PGSIZE.
 * @param flags The flags to set.
 * @param new_address The new address, must be a multiple of PGSIZE, and must be
 * in the range of the VMPL-VM virtual address space.
 * @return 0 on success, non-zero on failure.
 */
void *vmpl_vm_mremap(pte_t *root, void *old_address, size_t old_size,
					 size_t new_size, int flags, void *new_address)
{
	struct vmpl_vma_t *old_vma, *new_vma;
	struct vmpl_vm_t *vm = &vmpl_mm.vmpl_vm;
	void *ret;
	int rc;

	// Check that the address is not NULL
	if (old_address == NULL) {
		log_warn("old_address is NULL");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Align old address and size
	old_address = (void *)PAGE_ALIGN_DOWN((uintptr_t)old_address);
	new_address = (void *)PAGE_ALIGN_DOWN((uintptr_t)new_address);
	old_size = PAGE_ALIGN_UP(old_size);
	new_size = new_size ? PAGE_ALIGN_UP(new_size) : old_size;
	log_debug(VMPL_VM_MREMAP_FMT, old_address, old_address + old_size,
			new_address, new_address + new_size, flags);

	// Unsupported flags, (FIXME: Support these flags)
	if (flags & (MAP_FIXED | MAP_GROWSDOWN | MAP_STACK | MAP_HUGETLB)) {
		log_warn("Unsupported flags");
		errno = ENOTSUP;
		return MAP_FAILED;
	}

	// Check that the old address range is mapped
	old_vma = find_vma_intersection(vm, old_address, old_address + old_size);
	if (old_vma == NULL) {
		log_warn("The old address range is not mapped");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Check that the old address range belongs to the VMPL VM
	if ((old_address + old_size) <= vm->va_start ||
		 old_address >= vm->va_end) {
		log_warn("The old address range does not belong to the VMPL VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Align new address and size
	if (new_address != NULL) {
		log_debug(VMPL_VM_MREMAP_FMT, old_address, old_address + old_size,
				new_address, new_address + new_size, flags);
		
		// Check that the new address range is not already mapped
		new_vma = find_vma_intersection(vm, new_address, new_address + new_size);
		if (new_vma != NULL) {
			log_warn("The new address range is already mapped");
			errno = EEXIST;
			return MAP_FAILED;
		}

		// Check that the new address range belongs to the VMPL VM
		if ((new_address + new_size) <= vm->va_start ||
			 new_address >= vm->va_end) {
			log_warn("The new address range does not belong to the VMPL VM");
			errno = ENOMEM;
			return MAP_FAILED;
		}

		// Allocate new VMA for the new address range
		new_vma = alloc_vma_range(vm, new_address, new_size);
		if (new_vma == NULL) {
			log_warn("Failed to allocate new VMA");
			errno = ENOMEM;
			return MAP_FAILED;
		}
	} else {
		// Allocate new VMA for the new address range
		new_vma = alloc_vma(vm, new_size);
		if (new_vma == NULL) {
			log_warn("Failed to allocate new VMA");
			errno = ENOMEM;
			return MAP_FAILED;
		}

		new_address = (void *)new_vma->start;
	}

	// Populate the new VMA
	struct mremap_arg_t mremap_arg = {
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
		log_warn("Failed to walk the page table");
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
	new_vma->path = strdup(old_vma->path);

	// Insert new VMA into VMPL-VM
	bool inserted = insert_vma(vm, new_vma);
	if (!inserted) {
		log_warn("Failed to insert VMA into VMPL-VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Remove old VMA from VMPL-VM
	bool removed = remove_vma(vm, old_vma);
	if (!removed) {
		log_warn("Failed to remove VMA from VMPL-VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	vmpl_vma_free(old_vma);

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
		log_warn("addr is NULL");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Align address and length
	va_start = (void *)PAGE_ALIGN_DOWN((uintptr_t)addr);
	va_end = (void *)PAGE_ALIGN_UP((uintptr_t)addr + length);
	log_debug(VMPL_VM_MUNMAP_FMT, va_start, va_end);

	// Check that the address range belongs to the VMPL VM
	if (va_end <= vm->va_start || va_start >= vm->va_end) {
		log_warn("The address range does not belong to the VMPL VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Check that the address range is mapped
	vma = find_vma_intersection(vm, va_start, va_end);
	if (vma == NULL) {
		log_warn("The address range is not mapped");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	/* FIXME: Doesn't free as much memory as it could */
	ret = __vmpl_vm_page_walk(root, va_start, va_end - 1,
						&__vmpl_vm_free_helper, vma,
						3, CREATE_NONE);

	if (ret != 0) {
		log_warn("Failed to walk the page table");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Remove VMA from VMPL-VM
	bool removed = remove_vma(vm, vma);
	if (!removed) {
		log_warn("Failed to remove VMA from VMPL-VM");
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
		if (prot & PROT_WRITE)
			return -EINVAL;
		prot = PROT_NONE;
	}

	// Check that the address is not NULL
	if (addr == NULL) {
		log_warn("addr is NULL");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Align address and length
	va_start = (void *)PAGE_ALIGN_DOWN((uintptr_t)addr);
	va_end = (void *)PAGE_ALIGN_UP((uintptr_t)addr + len);
	log_debug(VMPL_VM_MPROTECT_FMT, va_start, va_end, prot);

	// Check that the address range belongs to the VMPL VM
	if (va_end <= vm->va_start || va_start >= vm->va_end) {
		log_warn("The address range does not belong to the VMPL VM");
		errno = ENOMEM;
		return MAP_FAILED;
	}

	// Check that the address range is mapped
	vma = find_vma_intersection(vm, va_start, va_end);
	if (vma == NULL) {
		log_warn("The address range is not mapped");
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
		log_warn("Failed to walk the page table");
		return ret;
	}

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
	struct vmpl_vm_t *vm = &vmpl_mm.vmpl_vm;

	log_debug("root = 0x%lx", root);
	newRoot = alloc_virt_page();
	log_debug("newRoot = 0x%lx", newRoot);
	memset(newRoot, 0, PGSIZE);

	log_debug("newRoot = 0x%lx", newRoot);
	// for each vma, walk the page table and clone the pages
	dict_itor *itor = dict_itor_new(vm->vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		log_debug(VMPL_VM_CLONE_FMT, vma->start, vma->end, vma->prot, vma->path);
		ret = __vmpl_vm_page_walk(root, vma->start, vma->end - 1,
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
	void *va_addr;
	struct vmpl_vma_t *vma = NULL;
	struct vmpl_vm_t *vm = &vmpl_mm.vmpl_vm;
	pte_t *pte = NULL;

	// Align address
	va_addr = (void *)PAGE_ALIGN_DOWN(addr);

	// Check if the faulting address is in the VMPL VM
	if (va_addr < vm->va_start || va_addr >= vm->va_end) {
		return -1;
	}

	// Find the page table entry for the faulting address
	rc = pgtable_lookup(vmpl_mm.pgd, (void *)va_addr, false, &pte);
	if (rc != 0) {
		return -1;
	}

	// Find the VMA that contains the faulting address 
	vma = find_vma_intersection(vm, va_addr, va_addr + PAGE_SIZE);
	if (!vma) {
		return -1;
	}

	rc = handle_cow_pgflt(addr, fec, pte);

	return -1;
}

struct vmpl_mm_t vmpl_mm = {.initialized = false};

/**
 * @brief Initialize the VMPL Memory Management. 
 * @note This function should be called before any other vmpl_mm_* functions.
 * @param vmpl_mm The vmpl_mm_t structure to initialize.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_mm_init(struct vmpl_mm_t *vmpl_mm)
{
    int rc;

	// VMPL Memory Management
	if (vmpl_mm->initialized)
		return 0;

    // VMPL Page Management
    rc = page_init(dune_fd);
    assert(rc == 0);

	// VMPL-VM Abstraction
	rc = vmpl_vm_init(&vmpl_mm->vmpl_vm);
	assert(rc == 0);

	// VMPL Page Table Management
    rc = pgtable_init(&vmpl_mm->pgd, dune_fd);
	assert(rc == 0);

	vmpl_mm->initialized = true;

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

void vmpl_mm_test_mmap(struct vmpl_mm_t *vmpl_mm)
{
	int rc;
	void *addr;
	// Test mmap
	log_info("Test mmap");
	addr = vmpl_vm_mmap(vmpl_mm->pgd, NULL, PGSIZE, PROT_READ | PROT_WRITE,
						MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(addr != MAP_FAILED);
	assert(addr == vmpl_mm->vmpl_vm.va_start);
	log_success("Test mmap passed");

	// Test vmpl_mm_stats
	vmpl_mm_stats(vmpl_mm);

	// Test mprotect
	log_info("Test mprotect");
	rc = vmpl_vm_mprotect(vmpl_mm->pgd, addr, PGSIZE, PROT_READ);
	assert(rc == 0);
	log_success("Test mprotect passed");

	// Test vmpl_mm_stats
	vmpl_mm_stats(vmpl_mm);

	// Test mremap
	log_info("Test mremap");
	addr = vmpl_vm_mremap(vmpl_mm->pgd, addr, PGSIZE, PGSIZE * 2, 0, NULL);
	assert(addr != MAP_FAILED);
	log_success("Test mremap passed");

	// Test vmpl_mm_stats
	vmpl_mm_stats(vmpl_mm);

	// Test munmap
	log_info("Test munmap");
	rc = vmpl_vm_munmap(vmpl_mm->pgd, addr, PGSIZE * 2);
	assert(rc == 0);
	log_success("Test munmap passed");

	// Test vmpl_mm_stats
	vmpl_mm_stats(vmpl_mm);
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