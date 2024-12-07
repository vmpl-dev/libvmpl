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
#include "globals.h"
#include "mmu.h"
#include "ghcb.h"
#include "vmpl.h"

extern const uint64_t TMP;
extern const uint64_t UFS_BASE;
extern const uint64_t KFS_BASE;
extern const uint64_t IN_USERMODE;
extern const uint64_t GHCB;
extern const uint64_t HOTCALL;

extern const uint64_t VMPL_PERCPU_GHCB;
extern const uint64_t VMPL_PERCPU_HOTCALL;

#define SAFE_STACK_SIZE (2048 * 1024)
#define XSAVE_SIZE 4096

extern __thread void *lpercpu;
#ifdef CONFIG_VMPL_CPUSET
int setup_cpuset();
#else
static inline int setup_cpuset(void) { return 0; }
#endif
void setup_gdt(uint64_t *gdt, struct Tss *tss);
void dump_gdt(uint64_t *gdt);
void dump_tss(struct Tss *tss);
int setup_safe_stack(struct Tss *tss);
void *create_percpu(void);
void free_percpu(void *percpu);
unsigned long get_fs_base(void);

#endif