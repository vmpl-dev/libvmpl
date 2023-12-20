#ifndef __VMPL_MM_H_
#define __VMPL_MM_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#define PGTABLE_MMAP_BASE 0x100000000000
#define PGTABLE_MMAP_SIZE 0x100000000000

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12
#define PAGE_MASK 0xfff
#define PAGE_ALIGN(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_OFFSET(addr) ((addr) & (PAGE_SIZE - 1))
#define PAGE_ROUND_UP(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ROUND_DOWN(addr) ((addr) & ~(PAGE_SIZE - 1))

void *vmpl_mmap(void *addr, size_t length, int prot, int flags, int fd,
				off_t offset);
void *vmpl_mremap(void *old_address, size_t old_size, size_t new_size,
				  int flags);
void vmpl_unmap(void *addr);

#endif