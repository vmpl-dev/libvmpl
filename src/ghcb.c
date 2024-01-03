#include <stdio.h>

#include "ghcb.h"
#include "log.h"

#ifdef CONFIG_DUMP_DETAILS
void dump_ghcb(struct Ghcb *ghcb)
{
    if (!ghcb) {
        log_warn("GHCB is NULL");
        return;
    }

    log_debug("GHCB dump:");
    log_debug("  cpl: %u", ghcb->cpl);
    log_debug("  rax: 0x%lx", ghcb->rax);
    log_debug("  rcx: 0x%lx", ghcb->rcx);
    log_debug("  rdx: 0x%lx", ghcb->rdx);
    log_debug("  rbx: 0x%lx", ghcb->rbx);
    log_debug("  sw_exit_code: 0x%lx", ghcb->sw_exit_code);
    log_debug("  sw_exit_info_1: 0x%lx", ghcb->sw_exit_info_1);
    log_debug("  sw_exit_info_2: 0x%lx", ghcb->sw_exit_info_2);
    log_debug("  sw_scratch: 0x%lx", ghcb->sw_scratch);
    log_debug("  xcr0: 0x%lx", ghcb->xcr0);
    log_debug("  version: %u", ghcb->version);
    log_debug("  usage: %u", ghcb->usage);
}
#endif