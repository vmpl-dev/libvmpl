#ifndef __VMPL_PAGE_H_
#define __VMPL_PAGE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/queue.h>
#include <assert.h>
#include <pthread.h>

#include "config.h"
#include "types.h"
#include "mmu.h"
#include "log.h"

typedef uint64_t physaddr_t;
typedef uintptr_t virtaddr_t;

#define PAGE_FLAG_MAPPED	0x1

// VMPL级别枚举
typedef enum vmpl_level {
	VMPL0 = 0,
    VMPL1 = 1,
    VMPL2 = 2,
    VMPL3 = 3,
    VMPL_MAX = VMPL3
} vmpl_level_t;

#define VMPL_BIT(vmpl) (1 << (vmpl))

// -----------------------VMPL COMMON-----------------------
SLIST_HEAD(page_head, page);
typedef SLIST_ENTRY(page) page_entry_t;

struct page {
	page_entry_t link;
    uint64_t ref : 60;      // reference count
    uint64_t flags : 1;     // page flags
    vmpl_level_t vmpl : 3;  // 使用枚举类型
};

// -----------------------PAGE MANAGER-----------------------
struct page_manager {
    struct page *pages;
    
    // VMPL页面管理
    pthread_mutex_t vmpl_mutex;
    struct page_head vmpl_free_list;
    int vmpl_page_count;
    
    // Dune页面管理 
    pthread_mutex_t dune_mutex;
    struct page_head dune_free_list;
    int dune_page_count;
    
    // 设备文件描述符
    int fd;

    // PAGEBASE属性
    uintptr_t pagebase;
};

extern struct page_manager *g_manager;

#define SYSTEM_RAM	0x480000000
#define PAGEBASE	0x0			/* 0 GB start */
#define PAGE_SHIFT	12
#define MAX_PAGES	(SYSTEM_RAM >> PAGE_SHIFT) /* 17 GB of memory */

extern void *do_mapping(uint64_t phys, size_t len);
static inline void __get_page(struct page *pg)
{
	assert(pg >= g_manager->pages);
	assert(pg < (g_manager->pages + MAX_PAGES));
	assert(pg->vmpl != VMPL0);

	pg->ref++;
}
static inline void __put_page(struct page *pg)
{
	assert(pg >= g_manager->pages);
	assert(pg < (g_manager->pages + MAX_PAGES));
	assert(pg->vmpl != VMPL0);
	assert(pg->ref > 0);

	pg->ref--;
}

// -----------------------VMPL PAGE MANAGEMENT-----------------------
extern int vmpl_page_init(void);
extern int vmpl_page_exit(void);
extern struct page * vmpl_page_alloc(void);
extern void vmpl_page_free(struct page *pg);
extern void vmpl_page_stats(void);

// 页面地址转换函数
extern struct page * vmpl_pa2page(physaddr_t pa);
extern physaddr_t vmpl_page2pa(struct page *pg);

extern bool vmpl_page_is_from_pool(physaddr_t pa);
extern bool vmpl_page_is_maped(physaddr_t pa);
static inline void vmpl_page_mark(struct page *pg)
{
	pg->vmpl = VMPL1;
	pg->ref = 0;
}
static inline void vmpl_page_mark_addr(physaddr_t pa)
{
	if (pa >= PAGEBASE)
		vmpl_page_mark(vmpl_pa2page(pa));
}
static inline void vmpl_page_get(struct page *pg)
{
	__get_page(pg);
}
static inline struct page * vmpl_page_get_addr(physaddr_t pa)
{
	struct page *pg;
	if (pa < PAGEBASE)
		return NULL;
	pg = vmpl_pa2page(pa);
	if (vmpl_page_is_from_pool(pa))
		vmpl_page_get(pg);
	return pg;
}
static inline void vmpl_page_put(struct page *pg)
{
	__put_page(pg);

	if (!pg->ref)
		vmpl_page_free(pg);
}
static inline void vmpl_page_put_addr(physaddr_t pa)
{
	struct page *pg = vmpl_pa2page(pa);
	if (vmpl_page_is_from_pool(pa))
		vmpl_page_put(pg);
}

// -----------------------DUNE PAGE MANAGEMENT-----------------------
extern int dune_page_init(void);
extern int dune_page_exit(void);
extern struct page * dune_page_alloc(void);
extern void dune_page_free(struct page *pg);
extern void dune_page_stats(void);
static inline void dune_page_put(struct page *pg)
{
	__put_page(pg);

	if (!pg->ref)
		dune_page_free(pg);
}

extern bool dune_page_is_from_pool(physaddr_t pa);
extern struct page * dune_pa2page(physaddr_t pa);
extern physaddr_t dune_page2pa(struct page *pg);
extern void dune_page_get(struct page *pg);

// -----------------------PAGE MANAGEMENT-----------------------
int page_init(int fd);
int page_exit(void);
void page_stats(void);
#ifdef CONFIG_VMPL_TEST
void page_test(void);
#else
static inline void page_test(void) {}
#endif

#endif