#ifndef PMM_H
#define PMM_H

#include "bitmap.h"

#define BITMAP_SIZE 512     // For 4KB pages

typedef struct {
    bmap *bitmap;
    void **pages;
} pmm;

pmm *pmm_init(void **pages);
void *pmm_alloc(pmm *manager);
void pmm_free(pmm *manager, const void *page);
int pmm_is_allocated(pmm *manager, const void *page);
void pmm_destroy(pmm *manager);

#endif // PMM_H