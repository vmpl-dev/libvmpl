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

#include "ioctl.h"
#include "svsm-dev.h"
#include "page.h"
#include "log.h"

struct page *pages;

// VMPL Page Management [Common Functions]
/**
 * @brief Map a page in the VMPL-VM and mark it as VMPL page.
 * @note The page must not be already mapped in the VMPL-VM.
 * @param fd VMPL device file descriptor
 * @param phys Physical address of the page
 * @param len Length of the page
 */
void* do_mapping(int fd, uint64_t phys, size_t len)
{
    void *addr;
    addr = mmap((void *)(PGTABLE_MMAP_BASE + phys), len,
                PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, phys);
    if (addr == MAP_FAILED) {
        perror("dune: failed to map pgtable");
    }

	// Mark as mapped in VMPL-VM
	log_debug("Marking page %lx-%lx as mapped", phys, phys + len);
	for (size_t i = 0; i < len; i += PGSIZE) {
		struct page *pg = vmpl_pa2page(phys + i);
		pg->flags = PAGE_FLAG_MAPPED;
	}

	return addr;
}

static int grow_pages(int fd, struct page_head *head, size_t num_pages, bool mapping)
{
	int rc;
	struct get_pages_t param;
	struct page *begin, *end, *pg;
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
	begin = vmpl_pa2page(param.phys);
	end = begin + num_pages;
	for (pg = begin; pg < end; pg++) {
		log_trace("Adding page %lx/%lx to free list", pg - begin, num_pages);
		vmpl_page_mark(pg);
		SLIST_INSERT_HEAD(head, pg, link);
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
	num_vmpl_pages--;

	return pg;
}

void vmpl_page_free(struct page *pg)
{
	assert(!pg->ref);
	pthread_mutex_lock(&vmpl_page_mutex);
	SLIST_INSERT_HEAD(&vmpl_pages_free, pg, link);
	pthread_mutex_unlock(&vmpl_page_mutex);
	num_vmpl_pages++;
}

void vmpl_page_stats(void) {
	printf("VMPL Pages Stats:\n");
	printf("VMPL Pages: %d/%ld\n", num_vmpl_pages, MAX_PAGES);
}

bool vmpl_page_is_from_pool(physaddr_t pa)
{
	struct page *pg;
	if (pa < PAGEBASE)
		return false;

	pg = vmpl_pa2page(pa);
	return pg->vmpl == Vmpl1 ? true : false;
}

bool vmpl_page_is_maped(physaddr_t pa)
{
	struct page *pg;
	if (pa < PAGEBASE)
		return false;

	pg = vmpl_pa2page(pa);
	return pg->flags == 1 ? true : false;
}

static void vmpl_page_test(int vmpl_fd)
{
	struct page *pg;
	assert(vmpl_fd > 0);

	log_info("VMPL Pages Test");
	pg = vmpl_page_alloc(vmpl_fd);
	assert(pg);
	assert(pg->ref == 1);
	assert(pg->vmpl == Vmpl1);

	vmpl_page_put(pg);
	assert(pg->ref == 0);
	assert(pg->vmpl == Vmpl1);
	log_success("VMPL Pages Test Passed");
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
	num_dune_pages--;

	return pg;
}

void dune_page_free(struct page *pg)
{
	assert(!pg->ref);
	pthread_mutex_lock(&page_mutex);
	SLIST_INSERT_HEAD(&dune_pages_free, pg, link);
	pthread_mutex_unlock(&page_mutex);
	num_dune_pages++;
}

void dune_page_stats(void)
{
	printf("Dune Pages Stats:\n");
	printf("Dune Pages: %d/%ld\n", num_dune_pages, MAX_PAGES);
}

static void dune_page_test(int vmpl_fd)
{
	struct page *pg;
	virtaddr_t va;
	assert(vmpl_fd > 0);

	log_info("Dune Page Test");
	pg = dune_page_alloc(vmpl_fd);
	assert(pg);
	assert(pg->ref == 1);
	assert(pg->vmpl == Vmpl1);

	dune_page_put(pg);
	assert(pg->ref == 0);
	assert(pg->vmpl == Vmpl1);
	log_success("Dune Page Test Passed");
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

int page_exit(void)
{
	free(pages);

	return 0;
}

void page_stats(void)
{
	printf("Page Stats:\n");
	vmpl_page_stats();
	dune_page_stats();
}

#ifdef CONFIG_VMPL_TEST
void page_test(int vmpl_fd)
{
	log_info("Page Test");
	vmpl_page_test(vmpl_fd);
	dune_page_test(vmpl_fd);
	log_success("Page Test Passed");
}
#endif