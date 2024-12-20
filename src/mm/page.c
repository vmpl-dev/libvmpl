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
#include "layout.h"

struct page_manager *g_manager = NULL;

// 创建页面管理器
static struct page_manager* page_manager_create(int fd, uintptr_t pagebase, size_t max_pages)
{
    struct page_manager *pm = malloc(sizeof(*pm));
    if (!pm) return NULL;

	// 获取页面描述符，用于VMPL页面管理，4KB页面
	pm->pages_desc = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
	                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!pm->pages_desc) {
		free(pm);
		return NULL;
	}
    
    pm->pages = malloc(sizeof(struct page) * max_pages);
    if (!pm->pages) {
        free(pm);
        return NULL;
    }

    pm->fd = fd;
    pm->pagebase = pagebase;
	pm->max_pages = max_pages;
    return pm;
}

static void page_manager_free(struct page_manager *pm)
{
	munmap(pm->pages_desc, PAGE_SIZE);
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
	struct pages_desc_t *param = pm->pages_desc;
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
	log_debug("num_pages: %lu", param->num_pages);

	// Add to free list
	size_t remaining_pages = num_pages;
    size_t page_idx = 0;

	while (remaining_pages > 0 && page_idx < 511) {
		struct page_desc_t *desc = &param->pages[page_idx];
		log_debug("desc->size: %u, desc->phys: %lx", desc->size, desc->phys);
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
		log_debug("Mapping pages: phys = 0x%lx, len = %lu", desc->phys, num_pages * PGSIZE);
		ptr = do_mapping(desc->phys, num_pages << PGSHIFT);
		if (!ptr) {
			log_err("Failed to map pages");
			return -ENOMEM;
		}
	}

	return 0;
}

bool __get_page(struct page *pg)
{
	if (!page_in_range(pg))
		return false;
	
	if (pg->vmpl == VMPL0)
		return false;
	
	pg->ref++;
	return true;
}

bool __put_page(struct page *pg)
{
	if (!page_in_range(pg))
		return false;
	
	if (pg->vmpl == VMPL0 || pg->ref == 0)
		return false;

	pg->ref--;
	return true;
}

// Dune Page Management [Common Functions]
static int dune_grow_pages(size_t num_pages)
{
	grow_pages(&g_manager->dune_free_list, num_pages, true);
	g_manager->dune_page_count += num_pages;
	return 0;
}

int dune_page_init(void)
{
	log_info("dune_page_init");

	// 初始化dune的page管理
	pthread_mutex_init(&g_manager->dune_mutex, NULL);
	SLIST_INIT(&g_manager->dune_free_list);
	g_manager->dune_page_count = 0;

	// 分配初始页面
	dune_grow_pages(CONFIG_DUNE_PAGE_GROW_SIZE);

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
		if (dune_grow_pages(CONFIG_DUNE_PAGE_GROW_SIZE)) {
			pthread_mutex_unlock(mutex);
			return NULL;
		}
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
	printf("Dune Pages: %d/%ld\n", g_manager->dune_page_count, g_manager->max_pages);
}

bool dune_page_is_from_pool(physaddr_t pa)
{
	return address_in_range(pa);
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
static int vmpl_grow_pages(size_t num_pages)
{
	grow_pages(&g_manager->vmpl_free_list, num_pages, true);
	g_manager->vmpl_page_count += num_pages;
	return 0;
}

int vmpl_page_init(void)
{
	log_info("vmpl_page_init");

	// 初始化vmpl的page管理
	pthread_mutex_init(&g_manager->vmpl_mutex, NULL);
	SLIST_INIT(&g_manager->vmpl_free_list);
	g_manager->vmpl_page_count = 0;

	// 分配初始页面
	vmpl_grow_pages(CONFIG_VMPL_PAGE_GROW_SIZE);

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
		if (vmpl_grow_pages(CONFIG_VMPL_PAGE_GROW_SIZE)) {
			pthread_mutex_unlock(mutex);
			return NULL;
		}
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
	printf("VMPL Pages: %d/%ld\n", g_manager->vmpl_page_count, g_manager->max_pages);
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

int page_manager_init(void)
{
	int ret;

	// 获取页面基址
	uintptr_t pagebase = get_pagebase();

	// 获取最大页面数
	uint64_t max_pages = get_max_pages();

	// 创建页面管理器，兼容dune的page管理
	g_manager = page_manager_create(dune_fd, pagebase, max_pages);
	if (!g_manager)
		return -ENOMEM;

	// 初始化vmpl的page管理
	ret = vmpl_page_init();
	if (ret)
		return ret;

	// 初始化dune的page管理
	ret = dune_page_init();
	if (ret)
		return ret;

	return 0;
}

int page_manager_exit(void)
{
	int rc;

	// 退出vmpl的page管理
	rc = vmpl_page_exit();
	if (rc)
		return rc;

	// 退出dune的page管理
	rc = dune_page_exit();
	if (rc)
		return rc;

	// 释放页面管理器
	page_manager_free(g_manager);

	return 0;
}

void page_manager_stats(void)
{
	// 打印vmpl的page管理统计信息
	vmpl_page_stats();

	// 打印dune的page管理统计信息
	dune_page_stats();
}

#ifdef CONFIG_VMPL_TEST
void page_manager_test(void)
{
	// 测试vmpl的page管理
	vmpl_page_test();

	// 测试dune的page管理
	dune_page_test();
}
#endif