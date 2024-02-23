#ifndef __VMPL_PAGE_H_
#define __VMPL_PAGE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/queue.h>
#include <assert.h>

#include "config.h"
#include "types.h"
#include "mmu-x86.h"

typedef uint64_t physaddr_t;
typedef uintptr_t virtaddr_t;

#define PAGE_FLAG_MAPPED	0x1

// -----------------------VMPL COMMON-----------------------
SLIST_HEAD(page_head, page);
typedef SLIST_ENTRY(page) page_entry_t;

struct page {
	page_entry_t link;
    uint64_t ref : 61;      // reference count
    uint64_t flags : 1;     // page flags
    uint64_t vmpl: 2;       // marked as vmpl page
};

extern struct page *pages;
extern int num_dune_pages;
extern int num_vmpl_pages;

#define PAGEBASE	0x0			/* 0 GB start */
#define MAX_PAGES	(2ul << 20) /* 8 GB of memory */

extern void *do_mapping(int fd, uint64_t phys, size_t len);
static inline void __get_page(struct page *pg)
{
	assert(pg >= pages);
	assert(pg < (pages + MAX_PAGES));
	assert(pg->vmpl == 1);

	pg->ref++;
}
static inline void __put_page(struct page *pg)
{
	assert(pg >= pages);
	assert(pg < (pages + MAX_PAGES));
	assert(pg->vmpl == 1);
	assert(pg->ref > 0);

	pg->ref--;
}

// -----------------------VMPL PAGE MANAGEMENT-----------------------
extern struct page * vmpl_page_alloc(int fd);
extern void vmpl_page_free(struct page *pg);
extern void vmpl_page_stats(void);

static inline struct page * vmpl_pa2page(physaddr_t pa)
{
	if (pa >= (PAGEBASE + (MAX_PAGES << PGSHIFT))) {
		printf("pa: %lx\n", pa);
	}
	assert(pa >= PAGEBASE);
	assert(pa < (PAGEBASE + (MAX_PAGES << PGSHIFT)));
	return &pages[PPN(pa - PAGEBASE)];
}
static inline physaddr_t vmpl_page2pa(struct page *pg)
{
	assert(pg >= pages);
	return PAGEBASE + ((pg - pages) << PGSHIFT);
}
extern bool vmpl_page_is_from_pool(physaddr_t pa);
extern bool vmpl_page_is_maped(physaddr_t pa);
static inline void vmpl_page_mark(struct page *pg)
{
	pg->vmpl = 1;
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
extern struct page * dune_page_alloc(int fd);
extern void dune_page_free(struct page *pg);
extern void dune_page_stats(void);
static inline void dune_page_put(struct page *pg)
{
	__put_page(pg);

	if (!pg->ref)
		dune_page_free(pg);
}

#define dune_pa2page			vmpl_pa2page
#define dune_page2pa			vmpl_page2pa
#define dune_page_isfrompool	vmpl_page_is_from_pool
#define dune_page_get			vmpl_page_get

// -----------------------PAGE MANAGEMENT-----------------------
int page_init(int fd);
int page_exit(void);
void page_stats(void);
#ifdef CONFIG_VMPL_TEST
void page_test(int vmpl_fd);
#else
static inline void page_test(int vmpl_fd) {}
#endif

#endif