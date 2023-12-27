#include <stdlib.h>
#include <string.h>

#include "pgtable.h"
#include "pmm.h"
#include "log.h"

static int uint64_t_cmp(const void *a, const void *b) {
    return *(uint64_t *)a - *(uint64_t *)b;
}

pmm *pmm_create(size_t num_pages, size_t max_num_areas) {
    log_debug("Creating PMM with %d pages and %d areas", num_pages, max_num_areas);
    pmm *manager = malloc(sizeof(pmm));
    if (!manager) return NULL;

    size_t size = num_pages * max_num_areas;
    manager->bitmap = bitmap_alloc(size);
    if (!manager->bitmap) {
        free(manager);
        return NULL;
    }

    manager->areas = malloc(max_num_areas * sizeof(uint64_t));
    manager->max_num_areas = max_num_areas;
	manager->num_areas = 0;
    manager->num_pages = num_pages;
    manager->num_used = 0;

	return manager;
}

void pmm_destroy(pmm *manager) {
    log_debug("Destroying PMM");
    bitmap_free(manager->bitmap);
    free(manager->areas);
    free(manager);
}

int pmm_add_area(pmm *manager, uint64_t start) {
    if (manager->num_areas == manager->max_num_areas) {
        log_debug("Cannot add area, max number of areas reached");
        return PMM_PAGE_ERROR;  // no more areas can be added
    }

    manager->areas[manager->num_areas++] = start >> PAGE_SHIFT;
    qsort(manager->areas, manager->num_areas, sizeof(uint64_t), uint64_t_cmp);
    log_debug("Added area at 0x%lx", start);
	return 0;
}

uint64_t pmm_alloc_area(pmm *manager) {
    size_t i = 0;
    for (i = 0; i < manager->num_pages; i++) {
        bitmap_set(manager->bitmap, i);
    }
    return manager->areas[0];
}

void pmm_free_area(pmm *manager, const uint64_t area) {
    size_t i = 0;
    for (i = 0; i < manager->num_pages; i++) {
        bitmap_clear(manager->bitmap, i);
    }
}

uint64_t pmm_alloc_page(pmm *manager) {
	int i = bitmap_find_first_zero(manager->bitmap);
	if (i != -1) {
        bitmap_set(manager->bitmap, i);
        uint64_t page = manager->areas[i >> 8] + (i % manager->num_pages);
        manager->num_used++;
        log_debug("Allocated page at 0x%lx", page);
        return page;
    }

    return PMM_PAGE_ERROR;  // no free pages
}

int pmm_free_page(pmm *manager, const uint64_t page) {
    int i = pmm_find_page(manager, page);
    if (i != PMM_PAGE_ERROR) {
        log_debug("Freed page at 0x%lx", page);
        bitmap_clear(manager->bitmap, i);
        manager->num_used--;
        return PMM_PAGE_FREE;
    }

    log_debug("Page 0x%lx can not be freed", page);
    return PMM_PAGE_ERROR;  // page not found
}

int pmm_find_page(pmm *manager, const uint64_t page) {
    // Do range check to make sure page is in the range of the manager
    if (page < manager->areas[0] || page >- manager->areas[manager->num_areas - 1] + manager->num_pages) {
        log_debug("Page 0x%lx is out of range", page);
        return PMM_PAGE_ERROR; // page not found
    }

    for (size_t i = 0; i < manager->num_areas; i++) {
        if (page >= manager->areas[i] && page < manager->areas[i] + manager->num_pages) {
            log_debug("Found page at 0x%lx", page);
            return i * manager->num_pages + (page - manager->areas[i]);
        }
    }

    log_debug("Page 0x%lx can not be found", page);
    return PMM_PAGE_ERROR;  // page not found
}

int pmm_is_allocated(pmm *manager, const uint64_t page) {
    int i = pmm_find_page(manager, page);
    if (i != -1) {
        if (bitmap_test(manager->bitmap, i)) {
            log_debug("Page 0x%lx is allocated", page);
            return PMM_PAGE_USED;
        }

        log_debug("Page 0x%lx is not allocated", page);
        return PMM_PAGE_FREE;
	}

    log_debug("Page 0x%lx is not allocated", page);
    return PMM_PAGE_ERROR;  // page not found
}

int pmm_self_test(pmm *test_manager) {
    // Allocate a page
    uint64_t page = pmm_alloc_page(test_manager);
    if (page == NULL) {
        pmm_destroy(test_manager);
        return 0;
    }

    // Check if the page is allocated
    if (pmm_is_allocated(test_manager, page) != PMM_PAGE_USED) {
        pmm_destroy(test_manager);
        return 0;
    }

    // Free the page
    if (pmm_free_page(test_manager, page) != PMM_PAGE_FREE) {
        pmm_destroy(test_manager);
        return 0;
    }

    // Check if the page is freed
    if (pmm_is_allocated(test_manager, page) != PMM_PAGE_FREE) {
        pmm_destroy(test_manager);
        return 0;
    }

    return 1;
}