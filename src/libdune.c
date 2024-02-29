#include "dune.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifdef LIBDUNE
static int dune_puts(const char *buf)
{
    long ret;

    ret = syscall(SYS_write, STDOUT_FILENO, buf, strlen(buf));

    return ret;
}

/**
 * dune_printf - a raw low-level printf request that uses a hypercall directly
 *
 * This is intended for working around libc syscall issues.
 */
int dune_printf(const char *fmt, ...)
{
    va_list args;
    char buf[1024];

    va_start(args, fmt);

    vsprintf(buf, fmt, args);

    return dune_puts(buf);
}

void * dune_mmap(void *addr, size_t length, int prot,
	     int flags, int fd, off_t offset)
{
    void *ret_addr;

    ret_addr = syscall(SYS_mmap, addr, length, prot, flags, fd, offset);

    return ret_addr;
}

void dune_die(void)
{
    syscall(SYS_exit);
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

#endif