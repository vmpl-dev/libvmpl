#include "vma.h"
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
	if (strncmp(path, "[stack", 6) == 0)
		return VMPL_VMA_TYPE_STACK;
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

// Frea vma
void free_vmpl_vma(struct vmpl_vma_t *vma)
{
	free(vma->path);
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

// First-Fit Algorithm
static uint64_t first_fit(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end) {
	uint64_t last_end = va_start;
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start > last_end && vma->start < va_end) {
			size_t free_size = vma->start - last_end;
			if (free_size >= size) {
				return last_end;
			}
		}
		last_end = vma->end;
	}
	if (va_end - last_end >= size) {
		return last_end;
	}
	return 0;
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
		if (vma->start > last_end && vma->start < va_end) {
			size_t free_size = vma->start - last_end;
			if (free_size >= size) {
				return last_end;
			}
		}
		last_end = vma->end;
		if (last_end >= va_end) {
			last_end = va_start;
		}
		if (last_end == original_last_end) {
			break;
		}
	}
	return 0;
}

// Best-Fit Algorithm
static uint64_t best_fit(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end) {
	uint64_t last_end = va_start;
	size_t best_size = UINTPTR_MAX;
	uint64_t best_start = 0;
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start > last_end && vma->start < va_end) {
			size_t free_size = vma->start - last_end;
			if (free_size >= size && free_size < best_size) {
				best_size = free_size;
				best_start = last_end;
			}
		}
		last_end = vma->end;
	}
	if (va_end - last_end >= size && va_end - last_end < best_size) {
		best_start = last_end;
	}
	return best_start;
}

// Worst-Fit Algorithm
static uint64_t worst_fit(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end) {
	uint64_t last_end = va_start;
	size_t worst_size = 0;
	uint64_t worst_start = 0;
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start > last_end && vma->start < va_end) {
			size_t free_size = vma->start - last_end;
			if (free_size >= size && free_size > worst_size) {
				worst_size = free_size;
				worst_start = last_end;
			}
		}
		last_end = vma->end;
	}
	if (va_end - last_end >= size && va_end - last_end > worst_size) {
		worst_start = last_end;
	}
	return worst_start;
}

// Random-Fit Algorithm
static uint64_t random_fit(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end) {
	uint64_t last_end = va_start;
	uint64_t random_start = 0;
	dict_itor *itor = dict_itor_new(vma_dict);
	for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
		struct vmpl_vma_t *vma = dict_itor_key(itor);
		if (vma->start > last_end && vma->start < va_end) {
			size_t free_size = vma->start - last_end;
			if (free_size >= size) {
				random_start = last_end;
				break;
			}
		}
		last_end = vma->end;
	}
	if (va_end - last_end >= size) {
		random_start = last_end;
	}
	return random_start;
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