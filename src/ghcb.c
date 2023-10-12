#include <stdio.h>

#include "ghcb.h"

void dump_ghcb(struct Ghcb *ghcb)
{
    if (!ghcb) {
        printf("GHCB is NULL\n");
        return;
    }

    printf("GHCB dump:\n");
    printf("  cpl: %u\n", ghcb->cpl);
    printf("  rax: 0x%lx\n", ghcb->rax);
    printf("  rcx: 0x%lx\n", ghcb->rcx);
    printf("  rdx: 0x%lx\n", ghcb->rdx);
    printf("  rbx: 0x%lx\n", ghcb->rbx);
    printf("  sw_exit_code: 0x%lx\n", ghcb->sw_exit_code);
    printf("  sw_exit_info_1: 0x%lx\n", ghcb->sw_exit_info_1);
    printf("  sw_exit_info_2: 0x%lx\n", ghcb->sw_exit_info_2);
    printf("  sw_scratch: 0x%lx\n", ghcb->sw_scratch);
    printf("  xcr0: 0x%lx\n", ghcb->xcr0);
    printf("  version: %u\n", ghcb->version);
    printf("  usage: %u\n", ghcb->usage);
}