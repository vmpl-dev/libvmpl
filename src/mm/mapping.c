#define _GNU_SOURCE
#include "log.h"
#include "vmpl-dev.h"
#include "mmu.h"
#include "page.h"
#include "pgtable.h"
#include "vm.h"
#include "mm.h"
#include "mapping.h"
#include "dune.h"
#include "vmpl.h"
#include "syscall.h"

uintptr_t phys_limit;
uintptr_t mmap_base;
uintptr_t start_stack;

static int map_phys(uintptr_t va, int len, int perm)
{
	uintptr_t pa = pgtable_va_to_pa(va);
    return vmpl_vm_map_phys(pgroot, (void *) va, len, (void *) pa, perm);
}

void map_ptr(void *p, int len)
{
	unsigned long page = PGADDR(p);
	unsigned long page_end = PGADDR((char*) p + len);
	unsigned long l = (page_end - page) + PGSIZE;
	void *pg = (void*) page;

	map_phys(pg, l, PERM_R | PERM_W);
}

static void map_stack_cb(const struct dune_procmap_entry *e)
{
	unsigned long esp;

	asm ("mov %%rsp, %0" : "=r" (esp));

	if (esp >= e->begin && esp < e->end)
		map_ptr((void*) e->begin, e->end - e->begin);
}

void map_stack(void)
{
	dune_procmap_iterate(map_stack_cb);
}

static void __setup_mappings_cb(const struct dune_procmap_entry *ent)
{
	int perm = PERM_NONE;
	int ret;

	// page region already mapped
	if (ent->begin == (unsigned long) PAGEBASE)
		return;
	
	if (ent->begin == (unsigned long) VSYSCALL_ADDR) {
		setup_vsyscall();
		return;
	}

	if (ent->type == PROCMAP_TYPE_VDSO) {
		map_phys(ent->begin, ent->end - ent->begin, PERM_U | PERM_R | PERM_X);
		return;
	}

	if (ent->type == PROCMAP_TYPE_VVAR) {
		map_phys(ent->begin, ent->end - ent->begin, PERM_U | PERM_R);
		return;
	}

	if (ent->r)
		perm |= PERM_R;
	if (ent->w)
		perm |= PERM_W;
	if (ent->x)
		perm |= PERM_X;

	map_phys(ent->begin, ent->end - ent->begin, perm);
	assert(!ret);
}

static int __setup_mappings_precise(void)
{
	int ret;

	ret = map_phys(PAGEBASE, MAX_PAGES * PGSIZE, PERM_R | PERM_W | PERM_BIG);
	if (ret)
		return ret;

	dune_procmap_iterate(&__setup_mappings_cb);

	return 0;
}

static void setup_vdso_cb(const struct dune_procmap_entry *ent)
{
	if (ent->type == PROCMAP_TYPE_VDSO) {
		map_phys(ent->begin, ent->end - ent->begin, PERM_U | PERM_R | PERM_X);
		return;
	}

	if (ent->type == PROCMAP_TYPE_VVAR) {
		map_phys(ent->begin, ent->end - ent->begin, PERM_U | PERM_R);
		return;
	}
}

static int __setup_mappings_full(struct dune_layout *layout)
{
	int ret;

	ret = map_phys(0, 1UL << 32, PERM_R | PERM_W | PERM_X | PERM_U);
	if (ret)
		return ret;

	ret = map_phys(layout->base_map, GPA_MAP_SIZE, PERM_R | PERM_W | PERM_X | PERM_U);
	if (ret)
		return ret;

	ret = map_phys(layout->base_stack, GPA_STACK_SIZE, PERM_R | PERM_W | PERM_X | PERM_U);
	if (ret)
		return ret;

	ret = map_phys(PAGEBASE, MAX_PAGES * PGSIZE, PERM_R | PERM_W | PERM_BIG);
	if (ret)
		return ret;

	dune_procmap_iterate(setup_vdso_cb);
	setup_vsyscall();

	return 0;
}

int setup_mappings(bool full)
{
	struct dune_layout layout;
	int ret = ioctl(dune_fd, DUNE_GET_LAYOUT, &layout);
	if (ret)
		return ret;

	phys_limit = layout.phys_limit;
	mmap_base = layout.base_map;
	start_stack = layout.base_stack;

	if (full)
		ret = __setup_mappings_full(&layout);
	else
		ret = __setup_mappings_precise();

	return ret;
}