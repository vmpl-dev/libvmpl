#include "vma.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <dict/dict.h>

// Get type of vma
int get_vmpl_vma_type(const char *path)
{
	if (path[0] != '[' && path[0] != '\0')
		return VMPL_VMA_TYPE_FILE;
	if (path[0] == '\0')
		return VMPL_VMA_TYPE_ANONYMOUS;
	if (strcmp(path, "[heap]") == 0)
		return VMPL_VMA_TYPE_HEAP;
	if (strncmp(path, "[stack", 6) == 0) {
		// Check if the path is exactly "[stack]" or starts with "[stack:"
		if (path[6] == '\0' || (path[6] == ':' && path[strlen(path) - 1] == ']'))
			return VMPL_VMA_TYPE_STACK;
	}
	if (strcmp(path, "[vsyscall]") == 0)
		return VMPL_VMA_TYPE_VSYSCALL;
	if (strcmp(path, "[vdso]") == 0)
		return VMPL_VMA_TYPE_VDSO;
	if (strcmp(path, "[vvar]") == 0)
		return VMPL_VMA_TYPE_VVAR;
	return VMPL_VMA_TYPE_UNKNOWN;
}

// Parse /proc/self/maps
int parse_procmaps(procmaps_callback_t callback, void *arg)
{
	FILE *maps_file;
	char *line = NULL;
	size_t len = 0;

	maps_file = fopen("/proc/self/maps", "r");
	if (!maps_file) {
		perror("fopen");
		return 1;
	}

	struct procmap_entry_t e;
	char read, write, execute, private;
	char path[256];

	while (getline(&line, &len, maps_file) != -1) {
		path[0] = '\0';
		sscanf(line, "%lx-%lx %c%c%c%c %08x %02x:%02x %d %s", &e.begin,
			   &e.end, &read, &write, &execute, &private,
			   &e.offset, &e.minor, &e.major, &e.inode, path);

		e.r = read == 'r';
		e.w = write == 'w';
		e.x = execute == 'x';
		e.p = private == 'p';
		e.path = strdup(path);
		e.type = get_vmpl_vma_type(path);

		callback(&e, arg);
	}

	fclose(maps_file);
	return 0;
}

struct vmpl_vma_t *vmpl_vma_new(const char *path)
{
	struct vmpl_vma_t *vma = malloc(sizeof(struct vmpl_vma_t));
	vma->start = 0;
	vma->end = 0;
	vma->prot = 0;
	vma->flags = 0;
	vma->minor = 0;
	vma->major = 0;
	vma->inode = 0;
	vma->offset = 0;
	vma->vm_file = strdup(path);
	return vma;
}

struct vmpl_vma_t *vmpl_vma_create(uint64_t va_start, size_t len, uint64_t prot,
								   uint64_t flags, int fd, uint64_t offset)
{
	struct vmpl_vma_t *vma = malloc(sizeof(struct vmpl_vma_t));
	vma->start = va_start;
	vma->end = va_start + len;
	vma->prot = prot;
	vma->flags = flags;
	vma->minor = 0;
	vma->major = 0;
	vma->inode = 0;
	vma->offset = offset;
	vma->vm_file = NULL;
	return vma;
}

struct vmpl_vma_t *vmpl_vma_clone(struct vmpl_vma_t *vma)
{
	struct vmpl_vma_t *new_vma = malloc(sizeof(struct vmpl_vma_t));
	new_vma->start = vma->start;
	new_vma->end = vma->end;
	new_vma->prot = vma->prot;
	new_vma->flags = vma->flags;
	new_vma->minor = vma->minor;
	new_vma->major = vma->major;
	new_vma->inode = vma->inode;
	new_vma->offset = vma->offset;
	new_vma->vm_file = strdup(vma->vm_file);
	return new_vma;
}

// Free vma
void vmpl_vma_free(struct vmpl_vma_t *vma)
{
	free(vma->vm_file);
	free(vma);
}

// Compare function for vma
int vmpl_vma_cmp(const void *a, const void *b)
{
	const struct vmpl_vma_t *va = a;
	const struct vmpl_vma_t *vb = b;

	if (va->start < vb->start) {
		return -1;
	} else if (va->start > vb->start) {
		return 1;
	} else {
		return 0;
	}
}

// Equality function for vma
int vmpl_vma_eq(const void *a, const void *b)
{
	const struct vmpl_vma_t *va = a;
	const struct vmpl_vma_t *vb = b;

	return (va->start == vb->start) && (va->end == vb->end);
}

/**
 * @brief  Check if two VMAs overlap.
 * @note VMPL-VM Helper API
 * @param a The first VMA.
 * @param b The second VMA.
 * @return 1 if the VMAs overlap, 0 otherwise.
 */
bool vmpl_vma_overlap(const void *a, const void *b)
{
	const struct vmpl_vma_t *va = a;
	const struct vmpl_vma_t *vb = b;

	return (va->start < vb->end) && (vb->start < va->end);
}

/**
 * @brief  Check if two VMAs are adjacent.
 * @note VMPL-VM Helper API
 * @param vma1 The first VMA.
 * @param vma2 The second VMA.
 * @return 1 if the VMAs are adjacent, 0 otherwise.
 */
bool are_vmas_adjacent(struct vmpl_vma_t *vma1, struct vmpl_vma_t *vma2)
{
	return vma1->end == vma2->start || vma2->end == vma1->start;
}

/**
 * @brief  Merge two adjacent VMAs into a single VMA.
 * @note VMPL-VM Helper API
 * @param vma1 The first VMA.
 * @param vma2 The second VMA.
 * @return The merged VMA if successful, NULL otherwise.
 */
struct vmpl_vma_t *merge_vmas(struct vmpl_vma_t *vma1, struct vmpl_vma_t *vma2)
{
	if (!are_vmas_adjacent(vma1, vma2)) {
		return NULL;
	}

	// Only merge VMAs if their protection flags are the same
	if (vma1->prot != vma2->prot) {
		return NULL;
	}

	struct vmpl_vma_t *merged_vma = malloc(sizeof(struct vmpl_vma_t));
	merged_vma->start = vma1->start < vma2->start ? vma1->start : vma2->start;
	merged_vma->end = vma1->end > vma2->end ? vma1->end : vma2->end;
	merged_vma->prot = vma1->prot; // Since vma1->prot == vma2->prot, we can use either
	merged_vma->offset = vma1->offset < vma2->offset ? vma1->offset : vma2->offset;
	merged_vma->vm_file = NULL; // TODO: Set the path if needed

	return merged_vma;
}

struct vmpl_vma_t *split_vma(struct vmpl_vma_t *vma, uint64_t addr)
{
	if (addr <= vma->start || addr >= vma->end) {
		return NULL;
	}

	struct vmpl_vma_t *split_vma = malloc(sizeof(struct vmpl_vma_t));
	split_vma->start = vma->start;
	split_vma->end = addr;
	split_vma->prot = vma->prot;
	split_vma->offset = vma->offset;
	split_vma->vm_file = NULL; // TODO: Set the path if needed

	vma->start = addr;

	return split_vma;
}

void dump_vmpl_vma(struct vmpl_vma_t *vma)
{
	printf(VMPL_VMA_FORMAT,
			vma->start, vma->end,
			vma->prot & PROT_READ? 'r' : '-',
			vma->prot & PROT_WRITE? 'w' : '-',
			vma->prot & PROT_EXEC? 'x' : '-',
			vma->offset, vma->minor, vma->major, vma->inode,
			vma->vm_file);
}

dict *get_vma_cache(void)
{
	static dict *vma_cache = NULL;
	if (!vma_cache) {
		vma_cache = rb_dict_new(vmpl_vma_cmp);
	}
	return vma_cache;
}

void vma_cache_add(struct vmpl_vma_t *vma)
{
	dict_insert(get_vma_cache(), vma);
}

void vma_cache_remove(struct vmpl_vma_t *vma)
{
	dict_remove(get_vma_cache(), vma);
}

struct vmpl_vma_t *vma_cache_lookup(uint64_t addr)
{
	struct vmpl_vma_t *vma = NULL;
	dict_itor *itor = dict_itor_new(get_vma_cache());
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		vma = dict_itor_key(itor);
		if (vma->start <= addr && addr < vma->end) {
			break;
		}
	}
	dict_itor_free(itor);
	return vma;
}

void vma_cache_dump(void)
{
	dict_itor *itor = dict_itor_new(get_vma_cache());
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		dump_vmpl_vma(vma);
	}
	dict_itor_free(itor);
}

// Allocate a new free block
struct free_block_t *free_block_new(uint64_t start, size_t size)
{
	struct free_block_t *free_block = malloc(sizeof(struct free_block_t));
	free_block->start = start;
	free_block->size = size;
	return free_block;
}

// Free a free block
void free_block_free(struct free_block_t *free_block)
{
	free(free_block);
}

// Compare function for free block
int free_block_cmp(const void *a, const void *b)
{
	const struct free_block_t *fa = a;
	const struct free_block_t *fb = b;

	if (fa->size < fb->size) {
		return -1;
	} else if (fa->size > fb->size) {
		return 1;
	} else {
		return 0;
	}
}

// Function to find free areas
dict *find_free_blocks(dict *vma_dict, uint64_t va_start, uint64_t va_end) {
	dict *free_blocks = rb_dict_new(free_block_cmp);
	struct free_block_t *free_block = NULL;
	uint64_t last_end = va_start;
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start >= last_end) {
			if (vma->start < va_end) {
				free_block = free_block_new(last_end, vma->start - last_end);
				dict_insert(free_blocks, free_block);
				last_end = vma->end;
			} else {
				// Out of range
				break;
			}
		}
	}
	if (last_end < va_end) {
		free_block = free_block_new(last_end, va_end - last_end);
		dict_insert(free_blocks, free_block);
	}
	dict_itor_free(itor);
	return free_blocks;
}

// First-Fit Algorithm
static uint64_t first_fit(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end) {
	uint64_t last_end = va_start;
	dict_itor *itor = dict_itor_new(vma_dict);
	uint64_t result = 0;
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start >= last_end) {
			if (vma->start < va_end) {
				size_t free_size = vma->start - last_end;
				if ((free_size >= size) && (last_end + size < va_end)) {
					result = last_end;
					break;
				}
			} else {
				// Out of range
				break;
			}
			last_end = vma->end;
		}
	}
	if (!result && (last_end + size <= va_end)) {
		result = last_end;
	}
	dict_itor_free(itor);
	return result;
}

// Next-Fit Algorithm
static uint64_t next_fit(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end) {
	static uint64_t last_end = 0;
	if (last_end < va_start || last_end >= va_end) {
		last_end = va_start;
	}
	uint64_t original_last_end = last_end;
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start > last_end && vma->start <= va_end) {
			size_t free_size = vma->start - last_end;
			if (free_size >= size && last_end + size <= va_end) {
				uint64_t result = last_end;
				last_end += size; // Update last_end to the end of the newly allocated block
				return result;
			}
		}
		if (vma->end > last_end && vma->end < va_end) {
			last_end = vma->end;
		}
		if (last_end >= va_end) {
			last_end = va_start;
		}
		if (last_end == original_last_end) {
			break;
		}
	}
	// If no suitable vma is found, allocate in the range [va_start, va_end)
	if (last_end == original_last_end && va_end - last_end >= size) {
		uint64_t result = last_end;
		last_end += size; // Update last_end to the end of the newly allocated block
		return result;
	}
	return 0;
}

// Best-Fit Algorithm
static uint64_t best_fit(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end) {
	uint64_t best_start = 0;
	size_t best_size = UINTPTR_MAX;
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start >= va_start && vma->end < va_end) {
			uint64_t free_size = vma->start - va_start;
			if (free_size >= size && free_size < best_size) {
				best_size = free_size;
				best_start = va_start;
			}
			va_start = vma->end;
		}
	}
	// Check the last free block
	if (va_end - va_start >= size && va_end - va_start < best_size) {
		best_start = va_start;
	}
	return best_start;
}

// Worst-Fit Algorithm
static uint64_t worst_fit(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end) {
	uint64_t worst_start = 0;
	size_t worst_size = 0;
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start >= va_start && vma->end < va_end) {
			uint64_t free_size = vma->start - va_start;
			if (free_size >= size && free_size > worst_size) {
				worst_size = free_size;
				worst_start = va_start;
			}
			va_start = vma->end;
		}
	}
	// Check the last free block
	if (va_end - va_start >= size && va_end - va_start > worst_size) {
		worst_start = va_start;
	}
	return worst_start;
}

// Random-Fit Algorithm
static uint64_t random_fit(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end) {
	// Collect all free blocks that are large enough
	struct free_block_t *free_block;
	dict *free_blocks = rb_dict_new(free_block_cmp);
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start >= va_start && vma->end < va_end) {
			uint64_t free_size = vma->start - va_start;
			if (free_size >= size) {
				free_block = free_block_new(va_start, free_size);
				dict_insert(free_blocks, free_block);
			}
			va_start = vma->end;
		}
	}
	// Check the last free block
	if (va_end - va_start >= size) {
		free_block = free_block_new(va_start, va_end - va_start);
		dict_insert(free_blocks, free_block);
	}

	// Randomly select a free block
	uint64_t random_start = 0;
	if (dict_count(free_blocks) > 0) {
		random_start = rand() % dict_count(free_blocks);
		dict_itor *itor = dict_itor_new(free_blocks);
		for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
			if (random_start == 0) {
				free_block = dict_itor_key(itor);
				random_start = free_block->start;
				break;
			}
			random_start--;
		}
		dict_itor_free(itor);
	}

	dict_free(free_blocks, free_block_free);
	return random_start;
}

// Parse fit algorithm
enum FitAlgorithm parse_fit_algorithm(const char *fit_algorithm, enum FitAlgorithm default_fit_algorithm) {
	if (strcmp(fit_algorithm, "first_fit") == 0) {
		return FIRST_FIT;
	} else if (strcmp(fit_algorithm, "next_fit") == 0) {
		return NEXT_FIT;
	} else if (strcmp(fit_algorithm, "best_fit") == 0) {
		return BEST_FIT;
	} else if (strcmp(fit_algorithm, "worst_fit") == 0) {
		return WORST_FIT;
	} else if (strcmp(fit_algorithm, "random_fit") == 0) {
		return RANDOM_FIT;
	} else {
		return default_fit_algorithm;
	}
}

// Fit Algorithms
static fit_algorithm_t fit_algorithms[] = {
	[FIRST_FIT] = first_fit,
	[NEXT_FIT] = next_fit,
	[BEST_FIT] = best_fit,
	[WORST_FIT] = worst_fit,
	[RANDOM_FIT] = random_fit,
};

// Fit Algorithm
fit_algorithm_t get_fit_algorithm(enum FitAlgorithm fit_algorithm) {
	return fit_algorithms[fit_algorithm];
}