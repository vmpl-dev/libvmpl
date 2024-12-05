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
#include "vmpl.h"

struct page_manager *g_manager = NULL;

// 创建页面管理器
static struct page_manager* page_manager_create(int fd, size_t pagebase)
{
    struct page_manager *pm = malloc(sizeof(*pm));
    if (!pm) return NULL;

	// 获取页面描述符，用于VMPL页面管理，4KB页面
	pm->get_pages = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
	                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!pm->get_pages) {
		free(pm);
		return NULL;
	}
    
    pm->pages = malloc(sizeof(struct page) * MAX_PAGES);
    if (!pm->pages) {
        free(pm);
        return NULL;
    }

    pm->fd = fd;
    pm->pagebase = pagebase;
    return pm;
}

static void page_manager_free(struct page_manager *pm)
{
	munmap(pm->get_pages, PAGE_SIZE);
    free(pm->pages);
    free(pm);
}

// VMPL Page Management [Common Functions]
/**
 * @brief Map a page in the VMPL-VM and mark it as VMPL page.
 * @note The page must not be already mapped in the VMPL-VM.
 * @param fd VMPL device file descriptor
 * @param phys Physical address of the page
 * @param len Length of the page
 */
void* do_mapping(uint64_t phys, size_t len)
{
    void *addr;
    addr = mmap((void *)(PGTABLE_MMAP_BASE + phys), len,
                PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, g_manager->fd, phys);
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

static int grow_pages(struct page_head *head, size_t num_pages, bool mapping)
{
	int rc;
	struct page_manager *pm = g_manager;
	struct get_pages_t *param = pm->get_pages;
	struct page *begin, *end, *pg;
	void *ptr;

	// Allocate more physical pages
	param->num_pages = num_pages;
	rc = vmpl_ioctl_get_pages(pm->fd, param);
	if (rc) {
		log_err("Failed to allocate %lu pages", num_pages);
		return -ENOMEM;
	}

	log_debug("Allocated %lu pages", num_pages);

	// Add to free list
	size_t remaining_pages = num_pages;
    size_t page_idx = 0;

	while (remaining_pages > 0 && page_idx < 511) {
		struct page_desc_t *desc = &param->pages[page_idx];
		// extract page from page descriptor
		size_t num_pages = 1 << desc->size; // 2^order
		begin = vmpl_pa2page(desc->phys);
		end = begin + num_pages;
		for (pg = begin; pg < end; pg++) {
			log_trace("Adding page %lx/%lx to free list", pg - begin, num_pages);
			vmpl_page_mark(pg);
			SLIST_INSERT_HEAD(head, pg, link);
		}

		remaining_pages -= num_pages;
		page_idx++;

		if (!mapping)
			continue;

		// Linear mapping
		log_debug("Mapping pages: phys = 0x%lx, len = %lu", desc->phys, desc->size * PGSIZE);
		ptr = do_mapping(desc->phys, desc->size << PGSHIFT);
		if (!ptr) {
			log_err("Failed to map pages");
			return -ENOMEM;
		}
	}

	return 0;
}

// 统一的页面分配接口
static struct page* page_manager_alloc(struct page_manager *pm, bool is_vmpl) 
{
	if (is_vmpl)
		return vmpl_page_alloc();
	else
		return dune_page_alloc();
}

// Dune Page Management [Common Functions]
int dune_page_init(void)
{
	log_info("dune_page_init");

	// 创建页面管理器，兼容dune的page管理
	g_manager = page_manager_create(dune_fd, PAGEBASE);
	if (!g_manager)
		return -ENOMEM;

	// 初始化dune的page管理
	g_manager->dune_page_count = 0;
	pthread_mutex_init(&g_manager->dune_mutex, NULL);
	SLIST_INIT(&g_manager->dune_free_list);

	// 分配初始页面
	grow_pages(&g_manager->dune_free_list, CONFIG_DUNE_PAGE_GROW_SIZE, true);

    return 0;
}

int dune_page_exit(void)
{
	return 0;
}

struct page * dune_page_alloc(void) 
{
	pthread_mutex_t *mutex = &g_manager->dune_mutex;
	struct page_head *free_list = &g_manager->dune_free_list;
	struct page *pg;
	pthread_mutex_lock(mutex);

	if (SLIST_EMPTY(free_list)) {
		if (grow_pages(free_list, CONFIG_DUNE_PAGE_GROW_SIZE, true)) {
			pthread_mutex_unlock(mutex);
			return NULL;
		}
		g_manager->dune_page_count += CONFIG_DUNE_PAGE_GROW_SIZE;
	}

	pg = SLIST_FIRST(free_list);
	SLIST_REMOVE_HEAD(free_list, link);
	pthread_mutex_unlock(mutex);

	dune_page_get(pg);
	g_manager->dune_page_count--;
	return pg;
}

void dune_page_free(struct page *pg)
{
	struct page_manager *pm = g_manager;
	pthread_mutex_lock(&pm->dune_mutex);
	SLIST_INSERT_HEAD(&pm->dune_free_list, pg, link);
	pm->dune_page_count++;
	pthread_mutex_unlock(&pm->dune_mutex);
}

void dune_page_stats(void)
{
	printf("Dune Pages Stats:\n");
	printf("Dune Pages: %d/%ld\n", g_manager->dune_page_count, MAX_PAGES);
}

bool dune_page_is_from_pool(physaddr_t pa)
{
	if (pa >= g_manager->pagebase && pa < (g_manager->pagebase + (MAX_PAGES << PGSHIFT)))
		return true;
	return false;
}

struct page * dune_pa2page(physaddr_t pa)
{
	return &g_manager->pages[PPN(pa - g_manager->pagebase)];
}

physaddr_t dune_page2pa(struct page *pg)
{
	return g_manager->pagebase + ((pg - g_manager->pages) << PGSHIFT);
}

void dune_page_get(struct page *pg)
{
	__get_page(pg);
}

static void dune_page_test(void)
{
	struct page *pg;
	assert(g_manager->fd > 0);

	log_info("Dune Page Test");
	pg = dune_page_alloc();
	assert(pg);
	assert(pg->ref == 1);
	assert(pg->vmpl == Vmpl1);

	dune_page_put(pg);
	assert(pg->ref == 0);
	assert(pg->vmpl == Vmpl1);
	log_success("Dune Page Test Passed");
}


// VMPL Page Management [Common Functions]
int vmpl_page_init(void)
{
	log_info("vmpl_page_init");

	// 初始化dune的page管理
	dune_page_init();

	// 初始化vmpl的page管理
	g_manager->vmpl_page_count = 0;
	pthread_mutex_init(&g_manager->vmpl_mutex, NULL);
	SLIST_INIT(&g_manager->vmpl_free_list);
	grow_pages(&g_manager->vmpl_free_list, CONFIG_VMPL_PAGE_GROW_SIZE, true);

	return 0;
}

int vmpl_page_exit(void)
{
	return dune_page_exit();
}

struct page* vmpl_page_alloc(void)
{
	pthread_mutex_t *mutex = &g_manager->vmpl_mutex;
	struct page_head *free_list = &g_manager->vmpl_free_list;
	struct page *pg;

	pthread_mutex_lock(mutex);

	if (SLIST_EMPTY(free_list)) {
		if (grow_pages(free_list, CONFIG_VMPL_PAGE_GROW_SIZE, true)) {
			pthread_mutex_unlock(mutex);
			return NULL;
		}
		g_manager->vmpl_page_count += CONFIG_VMPL_PAGE_GROW_SIZE;
	}

	pg = SLIST_FIRST(free_list);
	SLIST_REMOVE_HEAD(free_list, link);
	pthread_mutex_unlock(mutex);

	vmpl_page_get(pg);
	g_manager->vmpl_page_count--;
	return pg;
}

void vmpl_page_free(struct page *pg)
{
	struct page_manager *pm = g_manager;
	pthread_mutex_lock(&pm->vmpl_mutex);
	SLIST_INSERT_HEAD(&pm->vmpl_free_list, pg, link);
	pm->vmpl_page_count++;
	pthread_mutex_unlock(&pm->vmpl_mutex);
}

void vmpl_page_stats(void)
{
	printf("VMPL Pages Stats:\n");
	printf("VMPL Pages: %d/%ld\n", g_manager->vmpl_page_count, MAX_PAGES);
}

bool vmpl_page_is_from_pool(physaddr_t pa)
{
	struct page *pg = vmpl_pa2page(pa);
	return pg->vmpl != VMPL0;
}

bool vmpl_page_is_maped(physaddr_t pa)
{
	struct page *pg = vmpl_pa2page(pa);
	return pg->flags & PAGE_FLAG_MAPPED;
}

struct page * vmpl_pa2page(physaddr_t pa)
{
    return dune_pa2page(pa);
}

physaddr_t vmpl_page2pa(struct page *pg)
{
    return dune_page2pa(pg);
}

static void vmpl_page_test(void)
{
	struct page *pg;
	assert(g_manager->fd > 0);

	log_info("VMPL Pages Test");
	pg = vmpl_page_alloc();
	assert(pg);
	assert(pg->ref == 1);
	assert(pg->vmpl == Vmpl1);

	vmpl_page_put(pg);
	assert(pg->ref == 0);
	assert(pg->vmpl == Vmpl1);
	log_success("VMPL Pages Test Passed");
}
