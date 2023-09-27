#include "trap.h"

static dune_syscall_cb syscall_cb;

void dune_syscall_handler(struct dune_tf *tf)
{
    if (syscall_cb) {
        syscall_cb(tf);
    } else {
        // dune_printf("missing handler for system call - #%d\n", tf->rax);
        // dune_dump_trap_frame(tf);
        // dune_die();
    }
}