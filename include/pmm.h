#ifndef PMM_H
#define PMM_H

#include "bitmap.h"

#define BITMAP_SIZE 512     // For 4KB pages

typedef struct {
    bitmap *bitmap;
    uint64_t *pages;
} pmm;

pmm *pmm_init(uint64_t *pages);
uint64_t pmm_alloc(pmm *manager);
void pmm_free(pmm *manager, const uint64_t page);
int pmm_is_allocated(pmm *manager, const uint64_t page);
void pmm_destroy(pmm *manager);
int pmm_self_test();

#endif // PMM_H