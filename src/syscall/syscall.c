#include "vmpl.h"
#include "syscall.h"
#include "log.h"

#include <unistd.h>

long __vmpl_syscall(long sys_nr, struct syscall_args_t *args) {
    return syscall(sys_nr, args->a0, args->a1, args->a2, args->a3, args->a4, args->a5);
}

#ifdef CONFIG_DUNE_BOOT
int setup_syscall(bool map_full)
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
        uintptr_t pa = pgtable_va_to_pa(page + i);
        vmpl_vm_lookup(pgroot, (void *) (lstara + i), CREATE_NORMAL, &pte);
        *pte = PTE_ADDR(pa) | PTE_P | PTE_C;
    }

    if (!map_full)
        goto exit;

    log_info("setup vsyscall");
    vmpl_vm_lookup(pgroot, (void *) VSYSCALL_ADDR, CREATE_NORMAL, &pte);
    *pte = PTE_ADDR(pgtable_va_to_pa(&__dune_vsyscall_page)) | PTE_P | PTE_U | PTE_C;
    log_debug("dune: vsyscall at %p, pte = %lx", VSYSCALL_ADDR, *pte);

exit:
    return 0;
}

void setup_vsyscall(void)
{
    pte_t *pte;

    vmpl_vm_lookup(pgroot, (void *) VSYSCALL_ADDR, CREATE_NORMAL, &pte);
    *pte = PTE_ADDR(pgtable_va_to_pa(&__dune_vsyscall_page)) | PTE_P | PTE_U;
}
#endif