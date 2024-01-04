#include "pgtable.h"
#include "vm.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>

/**
 * @brief  Insert a VMA into the VMA dictionary of the VMPL-VM.
 * @note VMPL-VM Low Level API
 * @param vm The VMPL-VM to insert into.
 * @param vma The VMA to insert.
 */
bool insert_vma(struct vmpl_vm_t *vm, struct vmpl_vma_t *vma) {
	dict_insert_result result;
	assert(vm != NULL);
	assert(vma != NULL);
	assert(vma->start < vma->end);
	pthread_spin_lock(&vm->lock);
	result = dict_insert(vm->vma_dict, vma);
	pthread_spin_unlock(&vm->lock);
	return result.inserted;
}

/**
 * @brief  Lookup the first VMA that satisfies end_addr <= vma->end, NULL if not found.
 * @note VMPL-VM Low Level API
 * @param vm The VMPL-VM to search.
 * @param end_addr The address to search for.
 * @return The VMA if found, NULL otherwise.
 */
struct vmpl_vma_t *find_vma(struct vmpl_vm_t *vm, uint64_t end_addr) {
	struct vmpl_vma_t *vma = NULL;
	assert(vm != NULL);
	pthread_spin_lock(&vm->lock);
	dict_itor *itor = dict_itor_new(vm->vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		vma = dict_itor_key(itor);
		if (end_addr <= vma->end) {
			goto out;
		}
	}
out:
	dict_itor_free(itor);
	pthread_spin_unlock(&vm->lock);
	return vma;
}

/**
 * @brief Lookup the first VMA that intersects with the given range.
 * @note VMPL-VM Low Level API
 * @param vm The VMPL-VM to search.
 * @param vma The VMA to search for.
 * @param start_addr The start address of the intersection.
 * @param end_addr The end address of the intersection.
 * @return The VMA if found, NULL otherwise.
 */
struct vmpl_vma_t *find_vma_intersection(struct vmpl_vm_t *vm, uint64_t start_addr, uint64_t end_addr) {
	assert(vm != NULL);
	struct vmpl_vma_t *vma = find_vma(vm, end_addr);
	/* 
	 * The VMA dosen't intersect with the given range.
	 */
	if (vma && end_addr <= vma->start) {
		vma = NULL;
	}

	return vma;
}

/**
 * @brief  Remove a VMA from the VMA dictionary of the VMPL-VM.
 * @note VMPL-VM Low Level API
 * @param vm The VMPL-VM to remove from.
 * @param vma The VMA to remove.
 * @return None.
 */
bool remove_vma(struct vmpl_vm_t *vm, struct vmpl_vma_t *vma) {
	dict_remove_result result;
	assert(vm != NULL);
	assert(vma != NULL);
	pthread_spin_lock(&vm->lock);
	result = dict_remove(vm->vma_dict, vma);
	pthread_spin_unlock(&vm->lock);
	return result.removed;
}

/**
 * @brief  Get the size of a VMA.
 * @note VMPL-VM Helper API
 * @param vma The VMA to get the size of.
 * @return The size of the VMA.
 */
size_t get_vma_size(struct vmpl_vma_t *vma) {
	return vma->end - vma->start;
}

/**
 * @brief  Check if two VMAs are adjacent.
 * @note VMPL-VM Helper API
 * @param vma1 The first VMA.
 * @param vma2 The second VMA.
 * @return 1 if the VMAs are adjacent, 0 otherwise.
 */
bool are_vmas_adjacent(struct vmpl_vma_t *vma1, struct vmpl_vma_t *vma2) {
	return vma1->end == vma2->start || vma2->end == vma1->start;
}

/**
 * @brief  Merge two adjacent VMAs into a single VMA.
 * @note VMPL-VM Helper API
 * @param vma1 The first VMA.
 * @param vma2 The second VMA.
 * @return The merged VMA if successful, NULL otherwise.
 */
struct vmpl_vma_t *merge_vmas(struct vmpl_vma_t *vma1, struct vmpl_vma_t *vma2) {
	if (!are_vmas_adjacent(vma1, vma2)) {
		return NULL;
	}

	struct vmpl_vma_t *merged_vma = malloc(sizeof(struct vmpl_vma_t));
	merged_vma->start = vma1->start < vma2->start ? vma1->start : vma2->start;
	merged_vma->end = vma1->end > vma2->end ? vma1->end : vma2->end;
	merged_vma->prot = vma1->prot | vma2->prot;
	merged_vma->offset = vma1->offset < vma2->offset ? vma1->offset : vma2->offset;
	merged_vma->path = NULL; // TODO: Set the path if needed

	return merged_vma;
}

/**
 * @brief  Allocate a VMA from the VMPL-VM.
 * @note VMPL-VM Low Level API
 * @param vm The VMPL-VM to allocate from.
 * @param va_start The start address of the VMA to allocate.
 * @param size The size of the VMA to allocate.
 * @return The allocated VMA if successful, NULL otherwise.
 */
struct vmpl_vma_t *alloc_vma_range(struct vmpl_vm_t *vm, uint64_t va_start, size_t size) {
	struct vmpl_vma_t *vma;

	assert(vm != NULL);
	assert(va_start >= vm->va_start);
	assert(va_start < vm->va_end);
	assert(va_start + size <= vm->va_end);

	log_debug("va_start = 0x%lx, va_end = 0x%lx, size = 0x%lx", va_start, vm->va_end, size);
	va_start = vm->fit_algorithm(vm->vma_dict, size, va_start, vm->va_end);
	if (va_start == 0) {
		return NULL;
	}

	vma = malloc(sizeof(struct vmpl_vma_t));
	vma->start = va_start;
	vma->end = va_start + size;
	vma->prot = 0;
	vma->offset = 0;
	vma->path = NULL;
	return vma;
}

/**
 * @brief Insert a VMA into the VMA dictionary.
 * @param entry The procmap entry to insert.
 * @param arg The vmpl_vm_t structure to insert into.
 * @return 0 on success, non-zero on failure.
 */
static void insert_vma_callback(struct procmap_entry_t *entry, void *arg) {
	struct vmpl_vm_t *vm = arg;
	struct vmpl_vma_t *new_vma = malloc(sizeof(struct vmpl_vma_t));
	new_vma->start = entry->begin;
	new_vma->end = entry->end;
	new_vma->prot = entry->r | (entry->w << 1) | (entry->x << 2);
	new_vma->offset = entry->offset;
	new_vma->flags = entry->type;
	new_vma->minor = entry->minor;
	new_vma->major = entry->major;
	new_vma->inode = entry->inode;
	new_vma->path = strdup(entry->path);
	insert_vma(vm, new_vma);
}

/**
 * Initialize the virtual memory subsystem.
 * This function should be called before any other vmpl_vm_* functions.
 * @param vmpl_vm The vmpl_vm_t structure to initialize.
 * @return 0 on success, non-zero on failure.
 */
int vmpl_vm_init(struct vmpl_vm_t *vmpl_vm)
{
	int rc;
	char *va_start, *va_end;
	size_t size;
	struct vmpl_vma_t *vma;
	bool removed, inserted;

	// VMPL Preserve Kernel Mapping
	va_start = CONFIG_VMPL_VA_START;
	size = CONFIG_VMPL_VA_SIZE;
	log_debug("va_start = 0x%lx, size = 0x%lx", va_start, size);
	va_start = mmap(va_start, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (va_start == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	log_debug("va_start = 0x%lx, va_end = 0x%lx", va_start, va_start + size);

	// VMPL VMA Management
	vmpl_vm->va_start = va_start;
	vmpl_vm->va_end = va_start + size;
	vmpl_vm->fit_algorithm = get_fit_algorithm(CONFIG_VMPL_FIT_ALGORITHM);
	vmpl_vm->vma_dict = rb_dict_new(vmpl_vma_cmp);
	pthread_spin_init(&vmpl_vm->lock, PTHREAD_PROCESS_PRIVATE);
	rc = parse_procmaps(insert_vma_callback, vmpl_vm);
	if (rc != 0) {
		perror("parse_procmaps");
		return -1;
	}

	// Is sorted?
	bool is_sorted = dict_is_sorted(vmpl_vm->vma_dict);
	assert(is_sorted == true);

	// Remove the preserved mmaping from the VMA dictionary
	vma = find_vma_intersection(vmpl_vm, vmpl_vm->va_start, vmpl_vm->va_end);
	assert(vma != NULL);
	assert(vma->start == vmpl_vm->va_start && vma->end == vmpl_vm->va_end);
	removed = remove_vma(vmpl_vm, vma);
	assert(removed == true);

	// Add the preserved mmaping to the VMA dictionary
	vma = vmpl_vma_new("[pgtable]");
	vma->start = PGTABLE_MMAP_BASE;
	vma->end = PGTABLE_MMAP_BASE + PGTABLE_MMAP_SIZE;
	vma->prot = PROT_READ | PROT_WRITE;
	inserted = insert_vma(vmpl_vm, vma);
	assert(inserted == true);

	return 0;
}

/**
 * @brief  Free the virtual memory subsystem.
 * @note This function should be called after all other vmpl_vm_* functions.
 * @param vma The VMA to free.
 * @return None.
 */
int vmpl_vm_exit(struct vmpl_vm_t *vm)
{
	// VMPL VMA Management
	pthread_spin_destroy(&vm->lock);
	dict_clear(vm->vma_dict, vmpl_vma_free);
	dict_free(vm->vma_dict, vmpl_vma_free);
	munmap(vm->va_start, vm->va_end - vm->va_start);

	return 0;
}

/**
 * @brief  Print the VMA dictionary of the VMPL-VM.
 * @note VMPL-VM High Level API
 * @param vm The VMPL-VM to print.
 * @return None.
 */
void vmpl_vm_stats(struct vmpl_vm_t *vm)
{
	printf("VMPL-VM Stats:\n");
	printf("dict_count(vma_dict) = %d\n", dict_count(vm->vma_dict));
	pthread_spin_lock(&vm->lock);
	dict_itor *itor = dict_itor_new(vm->vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		vmpl_vma_print(dict_itor_key(itor));
	}
	dict_itor_free(itor);
	pthread_spin_unlock(&vm->lock);
}

void vmpl_vm_vma_test(struct vmpl_vm_t *vm, const char *algorithm)
{
	enum FitAlgorithm fit_algorithm;
	struct vmpl_vma_t *vma;
	uint64_t va_start, va_end;

	log_info("VMPL-VM VMA Test [algorithm = %s]", algorithm);
	fit_algorithm = parse_fit_algorithm(algorithm, FIRST_FIT);
	vm->fit_algorithm = get_fit_algorithm(fit_algorithm);
	log_info("Inserting 10 VMAs into the VMPL-VM");
	for (int i = 0; i < 10; i++) {
		va_start = vm->va_start + i * 0x1000;
		va_end = va_start + 0x1000;

		vma = alloc_vma(vm, 0x1000);
		assert(vma != NULL);
		log_debug("vma->start = 0x%lx, vma->end = 0x%lx", vma->start, vma->end);
		assert(vma->start == va_start && vma->end == va_end);
		bool inserted = insert_vma(vm, vma);
		assert(inserted == true);
		log_debug("inserted = %s", inserted ? "true" : "false");
	}
	log_info("Finding 10 VMAs from the VMPL-VM");
	for (int i = 0; i < 10; i++) {
		va_start = vm->va_start + i * 0x1000;
		va_end = va_start + 0x1000;

		vma = find_vma_intersection(vm, va_start, va_end);
		assert(vma != NULL);
		log_debug("vma->start = 0x%lx, vma->end = 0x%lx", vma->start, vma->end);
		assert(vma->start == va_start && vma->end == va_end);
	}
	log_info("Removing 10 VMAs from the VMPL-VM");
	for (int i = 0; i < 10; i++) {
		va_start = vm->va_start + i * 0x1000;
		va_end = va_start + 0x1000;

		vma = find_vma(vm, va_start);
		assert(vma != NULL);
		log_debug("vma->start = 0x%lx, vma->end = 0x%lx", vma->start, vma->end);
		assert(vma->start == va_start && vma->end == va_end);

		bool removed = remove_vma(vm, vma);
		assert(removed == true);
		log_debug("removed = %s", removed ? "true" : "false");

		vmpl_vma_free(vma);
	}
	log_success("VMPL-VM VMA Test [algorithm = %s] Passed", algorithm);
}

/**
 * @brief  Test the VMA dictionary of the VMPL-VM.
 * @note VMPL-VM High Level API
 * @param vm The VMPL-VM to test.
 * @return None.
 */
void vmpl_vm_test(struct vmpl_vm_t *vm)
{
	log_info("VMPL-VM Test");
	vmpl_vm_vma_test(vm, "first_fit");
	vmpl_vm_vma_test(vm, "next_fit");
	vmpl_vm_vma_test(vm, "best_fit");
	vmpl_vm_vma_test(vm, "worst_fit");
	vmpl_vm_vma_test(vm, "random_fit");
	log_success("VMPL-VM Test Passed");
	vm->fit_algorithm = get_fit_algorithm(CONFIG_VMPL_FIT_ALGORITHM);
}