#define _GNU_SOURCE
#include "dune.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

void dune_apic_ipi(uint32_t dest, uint32_t vector)
{
    apic_send_ipi(dest, vector);
}

void dune_apic_eoi(void)
{
    apic_eoi();
}

void dune_apic_init_rt_entry(void)
{
    apic_init_rt_entry();
}

uint32_t dune_apic_id_for_cpu(uint32_t cpu, bool *error)
{
    return apic_get_id_for_cpu(cpu, error);
}

void dune_apic_send_ipi(uint8_t vector, uint32_t dest_apic_id)
{
    apic_send_ipi(vector, dest_apic_id);
}

uint64_t dune_va_to_pa(uint64_t va)
{
    return pgtable_va_to_pa(va);
}

int dune_vm_mprotect(ptent_t *root, void *va, size_t len, int perm)
{
    return vmpl_vm_mprotect(root, va, len, perm);
}

int dune_vm_map_phys(ptent_t *root, void *va, size_t len, void *pa, int perm)
{
    return vmpl_vm_map_phys(root, va, len, pa, perm);
}

int dune_vm_map_pages(ptent_t *root, void *va, size_t len, int perm)
{
    return vmpl_vm_map_pages(root, va, len, perm);
}

void dune_vm_unmap(ptent_t *root, void *va, size_t len)
{
    return vmpl_vm_munmap(root, va, len);
}

int dune_vm_lookup(ptent_t *root, void *va, int create, ptent_t **pte_out)
{
    return vmpl_vm_lookup(root, va, create, pte_out);
}

int dune_vm_insert_page(ptent_t *root, void *va, struct page *pg, int perm)
{
    return vmpl_vm_insert_page(root, va, pg, perm);
}

struct page * dune_vm_lookup_page(ptent_t *root, void *va)
{
    return vmpl_vm_lookup_page(root, va);
}

ptent_t * dune_vm_clone(ptent_t *root)
{
    return vmpl_vm_clone(root);
}

void dune_vm_free(ptent_t *root)
{
    return vmpl_vm_free(root);
}

int dune_vm_page_walk(ptent_t *root, void *start_va, void *end_va,
			    page_walk_cb cb, const void *arg)
{
    return vmpl_vm_page_walk(root, start_va, end_va, cb, arg);
}

int dune_init(bool map_full)
{
    return vmpl_init(map_full);
}

int dune_enter()
{
    return vmpl_enter(1, NULL);
}