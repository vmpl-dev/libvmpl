#include <stdlib.h>
#include <string.h>

#include "pmm.h"

pmm *pmm_init(void **pages) {
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

void *pmm_alloc(pmm *manager) {
    for (size_t i = 0; i < BITMAP_SIZE; i++) {
        if (!bmap_test(manager->bitmap, i)) {
            bmap_set(manager->bitmap, i);
            return manager->pages[i];
        }
    }

    return NULL;  // no free pages
}

void pmm_free(pmm *manager, const void *page) {
    for (size_t i = 0; i < BITMAP_SIZE; i++) {
        if (manager->pages[i] == page) {
            bmap_clear(manager->bitmap, i);
            return;
        }
    }
}

int pmm_is_allocated(pmm *manager, const void *page) {
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