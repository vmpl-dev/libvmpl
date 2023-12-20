#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#include "pgtable.h"
#include "pmm.h"
#include "mm.h"

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

void vmpl_unmap(void *addr)
{
    // TODO: Implement memory allocator
}