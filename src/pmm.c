#include <stdlib.h>
#include <string.h>

#include "pmm.h"

pmm *pmm_init(uint64_t *pages) {
    pmm *manager = malloc(sizeof(pmm));
    if (!manager) return NULL;

    manager->bitmap = bmap_alloc(BITMAP_SIZE, BITMAP_TYPE_SIMPLE);
    if (!manager->bitmap) {
        free(manager);
        return NULL;
    }

    manager->pages = pages;

    return manager;
}

uint64_t pmm_alloc(pmm *manager) {
    for (size_t i = 0; i < BITMAP_SIZE; i++) {
        if (!bmap_test(manager->bitmap, i)) {
            bmap_set(manager->bitmap, i);
            return manager->pages[i];
        }
    }

    return NULL;  // no free pages
}

void pmm_free(pmm *manager, const uint64_t page) {
    for (size_t i = 0; i < BITMAP_SIZE; i++) {
        if (manager->pages[i] == page) {
            bmap_clear(manager->bitmap, i);
            return;
        }
    }
}

int pmm_is_allocated(pmm *manager, const uint64_t page) {
    for (size_t i = 0; i < BITMAP_SIZE; i++) {
        if (manager->pages[i] == page) {
            return bmap_test(manager->bitmap, i);
        }
    }

    return 0;  // page not found
}

void pmm_destroy(pmm *manager) {
    bmap_free(manager->bitmap);
    free(manager);
}

int pmm_self_test() {
    uint64_t *pages = malloc(BITMAP_SIZE * sizeof(uint64_t));
    if (!pages) return 0;

    memset(pages, 0xEF, BITMAP_SIZE * sizeof(uint64_t));

    pmm *test_manager = pmm_init(pages);
    if (!test_manager) {
        free(pages);
        return 0;
    }

    uint64_t page = pmm_alloc(test_manager);
    if (!page) {
        pmm_destroy(test_manager);
        free(pages);
        return 0;
    }

    if (!pmm_is_allocated(test_manager, page)) {
        pmm_destroy(test_manager);
        free(pages);
        return 0;
    }

    pmm_free(test_manager, page);
    if (pmm_is_allocated(test_manager, page)) {
        pmm_destroy(test_manager);
        free(pages);
        return 0;
    }

    pmm_destroy(test_manager);
    free(pages);
    return 1;
}