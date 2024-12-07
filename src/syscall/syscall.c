#define _GNU_SOURCE
#include "log.h"
#include "mmu.h"
#include "pgtable.h"
#include "vm.h"
#include "mm.h"
#include "syscall.h"
#include "vmpl.h"

#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <string.h>


long __vmpl_syscall(long sys_nr, struct syscall_args_t *args) {
    return syscall(sys_nr, args->a0, args->a1, args->a2, args->a3, args->a4, args->a5);
}

int setup_syscall()
{
    int rc;
    unsigned long lstar;
    unsigned long lstara;
    unsigned char *page;
    pte_t *pte;
    size_t off;
    int i;

    log_info("setup syscall");
    assert((unsigned long) __dune_syscall_end  -
           (unsigned long) __dune_syscall < PGSIZE);

    rc = dune_ioctl_get_syscall(dune_fd, &lstar);
    if (rc != 0)
        return -errno;

    log_debug("dune: lstar at %lx", lstar);
    page = mmap((void *) NULL, PGSIZE * 2,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANON, -1, 0);

    if (page == MAP_FAILED)
        return -errno;

    lstara = lstar & ~(PGSIZE - 1);
    off = lstar - lstara;

    memcpy(page + off, __dune_syscall,
        (unsigned long) __dune_syscall_end -
        (unsigned long) __dune_syscall);

    for (i = 0; i <= PGSIZE; i += PGSIZE) {
        rc = vmpl_vm_lookup(pgroot, (void *) (lstara + i), CREATE_NORMAL, &pte);
        if (rc) {
            log_err("dune: unable to lookup syscall at %lx", lstara + i);
            return rc;
        }
        uintptr_t pa = pgtable_va_to_pa(page + i);
        log_debug("dune: syscall at %p, pte = %lx", lstara + i, *pte);
        *pte = PTE_ADDR(pa) | PTE_P | PTE_C;
    }

    return 0;
}

int setup_vsyscall(void)
{
    int ret;
    pte_t *pte;

    ret = vmpl_vm_lookup(pgroot, (void *) VSYSCALL_ADDR, CREATE_NORMAL, &pte);
    if (ret) {
        log_err("dune: unable to lookup vsyscall");
        return ret;
    }

    *pte = PTE_ADDR(pgtable_va_to_pa(&__dune_vsyscall_page)) | PTE_P | PTE_U | PTE_C;
    log_debug("dune: vsyscall at %p, pte = %lx", VSYSCALL_ADDR, *pte);
    return 0;
}