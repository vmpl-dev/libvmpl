#ifndef PMM_H
#define PMM_H

#include "bitmap.h"

#define BITMAP_SIZE 512     // For 4KB pages

typedef struct {
    bitmap *bitmap;
    uint64_t *areas;
    size_t max_num_areas;
	size_t num_pages;
    size_t num_used;
	size_t num_areas;
} pmm;

#define PMM_PAGE_FREE 0
#define PMM_PAGE_USED 1
#define PMM_PAGE_ERROR -1

pmm *pmm_create(uint64_t num_pages, uint64_t num_areas);
void pmm_destroy(pmm *manager);
int pmm_add_area(pmm *manager, uint64_t start);
uint64_t pmm_alloc_page(pmm *manager);
int pmm_free_page(pmm *manager, const uint64_t page);
int pmm_find_page(pmm *manager, const uint64_t page);
int pmm_is_allocated(pmm *manager, const uint64_t page);
static inline size_t pmm_get_capacity(pmm *manager) {
    return manager->num_areas * manager->num_pages - manager->num_used;
}
int pmm_self_test(pmm *manager);

#endif // PMM_H