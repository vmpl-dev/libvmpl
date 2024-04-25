#ifndef __PERCPU_H__
#define __PERCPU_H__

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "mmu.h"
#include "ghcb.h"
#include "vmpl.h"

struct dune_percpu {
	uint64_t percpu_ptr;
	uint64_t tmp;
	uint64_t kfs_base;
	uint64_t ufs_base;
	uint64_t in_usermode;
	struct Tss tss;
	uint64_t gdt[NR_GDT_ENTRIES];
    struct Ghcb *ghcb;
	hotcall_t hotcall;
    struct fpu_area *fpu;
    char *xsave_area;
    uint64_t xsave_mask;
    int pkey;
    int vcpu_fd;
} __attribute__((packed));

#define DUNE_PERCPU_GHCB    216
#define DUNE_PERCPU_HOTCALL 224

#define SAFE_STACK_SIZE (2048 * 1024)
#define XSAVE_SIZE 4096

extern __thread struct dune_percpu *percpu;
void setup_idt(void);
struct dune_percpu *vmpl_alloc_percpu(void);
#ifdef CONFIG_VMPL_HOTCALLS
void hotcalls_enable(struct dune_percpu *percpu);
#else
static inline void hotcalls_enable(struct dune_percpu *percpu) {
	percpu->hotcall = NULL;
}
#endif
int do_dune_enter();

#endif