#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "pgtable.h"
#include "pmm.h"
#include "mm.h"
#include "log.h"

/**
 * 堆内存分配主要区分mmap和异常处理两种情况；
 * 可以用自主管理物理内存，接管堆内存的缺页异常；
 * 用自主管理页表页，处理mmap的情况，以及需要用户态clone页表的情况；
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
    }

    log_info("Heap range: %lx-%lx", vmpl_vm->heap_start, vmpl_vm->heap_end);

    fclose(maps_file);
    return 0;
}

void *vmpl_mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
    // TODO: Implement memory allocator

	return NULL;
}

void *vmpl_mremap(void *old_address, size_t old_size, size_t new_size, int flags)
{
    // TODO: Implement memory allocator

	return NULL;
}

int vmpl_munmap(void *addr, size_t length)
{
    // TODO: Implement memory allocator

    return 0;
}