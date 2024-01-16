#ifndef __VMPL_VMA_H__
#define __VMPL_VMA_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <dict/dict.h>

#define PERM_NONE  	    0	    /* no access */
#define PERM_R		    0x0001	/* read permission */
#define PERM_W		    0x0002	/* write permission */
#define PERM_X		    0x0004	/* execute permission */
#define PERM_U		    0x0008	/* user-level permission */
#define PERM_UC		    0x0010  /* make uncachable */
#define PERM_COW	    0x0020	/* COW flag */
#define PERM_USR1	    0x1000  /* User flag 1 */
#define PERM_USR2	    0x2000  /* User flag 2 */
#define PERM_USR3	    0x3000  /* User flag 3 */
#define PERM_BIG	    0x0100	/* Use large pages */
#define PERM_BIG_1GB	0x0200	/* Use large pages (1GB) */

// Helper Macros
#define PERM_SCODE	(PERM_R | PERM_X)
#define PERM_STEXT	(PERM_R | PERM_W)
#define PERM_SSTACK	PERM_STEXT
#define PERM_UCODE	(PERM_R | PERM_U | PERM_X)
#define PERM_UTEXT	(PERM_R | PERM_U | PERM_W)
#define PERM_USTACK	PERM_UTEXT

#define VMPL_VMA_TYPE_FILE      1
#define VMPL_VMA_TYPE_ANONYMOUS 2
#define VMPL_VMA_TYPE_HEAP		3
#define VMPL_VMA_TYPE_STACK 	4
#define VMPL_VMA_TYPE_VSYSCALL  5
#define VMPL_VMA_TYPE_VDSO		6
#define VMPL_VMA_TYPE_VVAR		7
#define VMPL_VMA_TYPE_UNKNOWN	8

// procmaps
struct procmap_entry_t {
	uint64_t begin;
	uint64_t end;
	uint32_t offset;
	bool r; // Readable
	bool w; // Writable
	bool x; // Executable
	bool p; // Private (or shared)
	uint32_t minor;  // New field for device
	uint32_t major;  // New field for device
	uint32_t inode;  // New field for inode
	char *path;
	int type;
};

typedef void (*procmaps_callback_t)(struct procmap_entry_t *, void *);
int parse_procmaps(procmaps_callback_t callback, void *arg);

// vma
struct vmpl_vma_t {
	uint64_t start;
	uint64_t end;
	uint32_t offset;
	uint64_t prot;
	uint64_t flags;
	uint32_t minor;  // New field for device
	uint32_t major;  // New field for device
	uint32_t inode;  // New field for inode
	char *path;
};

#define VMPL_VMA_INIT(start, end, flags, prot, offset, vmpl_vma_flags) \
	struct vmpl_vma_t { \
		.start = start, \
		.end = end, \
		.flags = flags, \
		.prot = prot, \
		.offset = offset, \
		.vmpl_vma_flags = vmpl_vma_flags, \
		.name = NULL, \
	}
#define VMPL_VMA_FORMAT "vmpl-vma: %lx-%lx %c%c%c %08x %02x:%02x %-8d %s\n"

static inline uint64_t get_vmpl_vma_len(struct vmpl_vma_t *vma)
{
	return vma->end - vma->start;
}
static inline size_t get_vma_size(struct vmpl_vma_t *vma) {
	return vma->end - vma->start;
}
static inline void vmpl_vma_print(struct vmpl_vma_t *vma)
{
	printf(VMPL_VMA_FORMAT, 
			vma->start, vma->end, 
			vma->prot & PROT_READ? 'r' : '-',
			vma->prot & PROT_WRITE? 'w' : '-',
			vma->prot & PROT_EXEC? 'x' : '-',
			vma->offset, vma->minor, vma->major, vma->inode,
			vma->path);
}
static inline void vmpl_vma_dump(struct vmpl_vma_t *vma)
{
	printf(VMPL_VMA_FORMAT, 
			vma->start, vma->end, 
			vma->prot & PROT_READ? 'r' : '-',
			vma->prot & PROT_WRITE? 'w' : '-',
			vma->prot & PROT_EXEC? 'x' : '-',
			vma->offset, vma->minor, vma->major, vma->inode,
			vma->path);
}
extern int get_vmpl_vma_type(const char *path);
extern struct vmpl_vma_t *vmpl_vma_new(const char *path);
extern struct vmpl_vma_t *vmpl_vma_create(uint64_t va_start, size_t len, uint64_t prot,
										  uint64_t flags, int fd, uint64_t offset);
extern struct vmpl_vma_t *vmpl_vma_clone(struct vmpl_vma_t *vma);
extern void vmpl_vma_free(struct vmpl_vma_t *vma);
extern int vmpl_vma_cmp(const void *a, const void *b);
extern int vmpl_vma_eq(const void *a, const void *b);
extern bool vmpl_vma_overlap(const void *a, const void *b);
extern bool are_vmas_adjacent(struct vmpl_vma_t *vma1, struct vmpl_vma_t *vma2);
extern struct vmpl_vma_t *merge_vmas(struct vmpl_vma_t *vma1, struct vmpl_vma_t *vma2);
extern struct vmpl_vma_t *split_vma(struct vmpl_vma_t *vma, uint64_t addr);
extern void dump_vmpl_vma(struct vmpl_vma_t *vma);
static inline bool range_in_vma(struct vmpl_vma_t *vma, uint64_t start, uint64_t end)
{
	return (vma->start <= start && end <= vma->end);
}

// vma cache
extern dict *get_vma_cache(void);
extern void vma_cache_add(struct vmpl_vma_t *vma);
extern void vma_cache_remove(struct vmpl_vma_t *vma);
extern struct vmpl_vma_t *vma_cache_lookup(uint64_t addr);
extern void vma_cache_dump(void);

// free block
struct free_block_t {
	uint64_t start;
	size_t size;
};

#define FREE_BLOCK_INIT(start, size) \
	struct free_block_t { \
		.start = start, \
		.size = size, \
	}

extern struct free_block_t *free_block_new(uint64_t start, size_t size);
extern int free_block_cmp(const void *a, const void *b);
extern dict *find_free_blocks(dict *vma_dict, uint64_t va_start, uint64_t va_end);

// fit algorithm
enum FitAlgorithm {
	FIRST_FIT,
	NEXT_FIT,
	BEST_FIT,
	WORST_FIT,
	RANDOM_FIT,
};

typedef uint64_t (*fit_algorithm_t)(dict *vma_dict, size_t size, uint64_t va_start, uint64_t va_end);
extern enum FitAlgorithm parse_fit_algorithm(const char *fit_algorithm, enum FitAlgorithm default_fit_algorithm);
extern fit_algorithm_t get_fit_algorithm(enum FitAlgorithm fit_algorithm);

#endif // __VMPL_VMA_H__