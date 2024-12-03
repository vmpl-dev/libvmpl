#ifndef __VMPL_MAPPING_H_
#define __VMPL_MAPPING_H_
#pragma once

extern uintptr_t phys_limit;
extern uintptr_t mmap_base;
extern uintptr_t start_stack;

// map a pointer to the current process
void map_ptr(void *p, int len);

// map the stack of the current process
void map_stack(void);

// setup all mappings
int setup_mappings(bool full);

#endif
