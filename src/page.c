/*
 * page.c - page management
 * vmpl-dune fused memory management
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>

#include "vmpl-ioctl.h"
#include "svsm-dev.h"
#include "page.h"
#include "log.h"

struct page *pages;

// VMPL Page Management [Common Functions]
void* do_mapping(int fd, uint64_t phys, size_t len)
{
    void *addr;
    addr = mmap((void *)(PGTABLE_MMAP_BASE + phys), len,
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, phys);
    if (addr == MAP_FAILED) {
        perror("dune: failed to map pgtable");
        return NULL;
    }

    return addr;
}

static int grow_pages(int fd, struct page_head *head, size_t num_pages, bool mapping)
{
	int rc;
	struct get_pages_t param;
	size_t begin, end;
	void *ptr;

	// Allocate more physical pages
	param.num_pages = num_pages;
	rc = vmpl_ioctl_get_pages(fd, &param);
	if (rc) {
		log_err("Failed to allocate %lu pages", num_pages);
		return -ENOMEM;
	}

	log_debug("Allocated %lu pages, phys = 0x%lx", num_pages, param.phys);

	// Add to free list
	begin = PPN(param.phys - PAGEBASE);
	end = begin + num_pages;
	for (size_t i = begin; i < end; i++) {
		log_trace("Adding page %lx/%lx", i, MAX_PAGES);
		pages[i].ref = 0;
		pages[i].vmpl = Vmpl1;
		SLIST_INSERT_HEAD(head, &pages[i], link);
	}

	if (!mapping)
		return 0;

	// Linear mapping
	log_debug("Mapping pages: phys = 0x%lx, len = %lu", param.phys, num_pages * PGSIZE);
	ptr = do_mapping(fd, param.phys, num_pages << PGSHIFT);
	if (!ptr) {
		log_err("Failed to map pages");
		return -ENOMEM;
	}

	return 0;
}

// VMPL Page Management [Physical Pages]
static pthread_mutex_t vmpl_page_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct page_head vmpl_pages_free;
int num_vmpl_pages;

static int vmpl_grow_pages(int fd)
{
	int rc;
	size_t num_pages = CONFIG_VMPL_PAGE_GROW_SIZE;

	rc = grow_pages(fd, &vmpl_pages_free, num_pages, false);
	if (rc)
		return rc;

	num_vmpl_pages += num_pages;
	return 0;
}

static inline int vmpl_page_init(int fd)
{
	SLIST_INIT(&vmpl_pages_free);
	num_vmpl_pages = 0;

	return vmpl_grow_pages(fd);
}

struct page * vmpl_page_alloc(int fd) {
	struct page *pg;

	pthread_mutex_lock(&vmpl_page_mutex);
	if (SLIST_EMPTY(&vmpl_pages_free)) {
		if (vmpl_grow_pages(fd)) {
			pthread_mutex_unlock(&vmpl_page_mutex);
			return NULL;
		}
	}

	pg = SLIST_FIRST(&vmpl_pages_free);
	SLIST_REMOVE_HEAD(&vmpl_pages_free, link);
	pthread_mutex_unlock(&vmpl_page_mutex);

	vmpl_page_get(pg);

	return pg;
}

void vmpl_page_free(struct page *pg)
{
	assert(!pg->ref);
	pthread_mutex_lock(&vmpl_page_mutex);
	SLIST_INSERT_HEAD(&vmpl_pages_free, pg, link);
	pthread_mutex_unlock(&vmpl_page_mutex);
}

void vmpl_page_stats(void) {
	printf("VMPL pages: %d/%ld\n", num_vmpl_pages, MAX_PAGES);
}

bool vmpl_page_isfrompool(physaddr_t pa)
{
	return pages[pa >> PGSHIFT].vmpl == Vmpl1;
}

static void vmpl_page_test(int vmpl_fd)
{
	struct page *pg;
	assert(vmpl_fd > 0);

	pg = vmpl_page_alloc(vmpl_fd);
	assert(pg);
	assert(pg->ref == 1);
	assert(pg->vmpl == Vmpl1);

	vmpl_page_free(pg);
	assert(pg->ref == 0);
	assert(pg->vmpl == Vmpl1);
}

// Dune Page Management	[Linear Mapped Pages]
static pthread_mutex_t page_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct page_head dune_pages_free;
int num_dune_pages;

static int dune_grow_pages(int fd)
{
	int rc;
	size_t num_pages = CONFIG_DUNE_PAGE_GROW_SIZE;
	rc = grow_pages(fd, &dune_pages_free, num_pages, true);
	if (rc)
		return rc;

	num_dune_pages += num_pages;
	return 0;
}

int dune_page_init(int fd)
{
	SLIST_INIT(&dune_pages_free);
	num_dune_pages = 0;

	return dune_grow_pages(fd);
}

struct page * dune_page_alloc(int fd)
{
	struct page *pg;

	pthread_mutex_lock(&page_mutex);
	if (SLIST_EMPTY(&dune_pages_free)) {
		if (dune_grow_pages(fd)) {
			pthread_mutex_unlock(&page_mutex);
			return NULL;
		}
	}

	pg = SLIST_FIRST(&dune_pages_free);
	SLIST_REMOVE_HEAD(&dune_pages_free, link);
	pthread_mutex_unlock(&page_mutex);

	dune_page_get(pg);

	return pg;
}

void dune_page_free(struct page *pg)
{
	assert(!pg->ref);
	pthread_mutex_lock(&page_mutex);
	SLIST_INSERT_HEAD(&dune_pages_free, pg, link);
	pthread_mutex_unlock(&page_mutex);
}

void dune_page_stats(void)
{
	printf("Dune pages: %d/%ld\n", num_dune_pages, MAX_PAGES);
}

static void dune_page_test(int vmpl_fd)
{
	struct page *pg;
	assert(vmpl_fd > 0);

	pg = dune_page_alloc(vmpl_fd);
	assert(pg);
	assert(pg->ref == 1);
	assert(pg->vmpl == Vmpl0);

	dune_page_free(pg);
	assert(pg->ref == 0);
	assert(pg->vmpl == Vmpl0);
}

// Page Management [General]
int page_init(int fd)
{
	pages = malloc(sizeof(struct page) * MAX_PAGES);
	if (!pages)
		goto err;

	if (vmpl_page_init(fd))
		goto err;

	if (dune_page_init(fd))
		goto err;

	return 0;
err:
	printf("Failed to initialize page management\n");
	free(pages);
	return -ENOMEM;
}

void page_exit(void)
{
	free(pages);
}

void page_stats(void)
{
	vmpl_page_stats();
	dune_page_stats();
}

void page_test(int vmpl_fd)
{
	vmpl_page_test(vmpl_fd);
	dune_page_test(vmpl_fd);
}