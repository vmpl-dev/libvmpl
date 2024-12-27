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

#define container_of(ptr, type, member) ({ \
    const typeof(((type *)0)->member) *__mptr = (ptr); \
    (type *)((char *)__mptr - offsetof(type, member)); })

struct percpu {
    uint64_t percpu_ptr;
    uint64_t tmp;
    uint64_t kfs_base;
    uint64_t ufs_base;
    uint64_t in_usermode;
    struct Tss tss;
    uint64_t gdt[NR_GDT_ENTRIES];
} __attribute__((packed));

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

#ifdef CONFIG_VMPL_CPUSET
int setup_cpuset();
#else
static inline int setup_cpuset(void) { return 0; }
#endif
void *create_percpu(void);
int init_percpu(struct percpu *base);
int free_percpu(struct percpu *base);
void dump_percpu(struct percpu *base);
void boot_percpu(struct percpu *base);
struct vcpu_config *vcpu_config_alloc(struct percpu *base);
struct percpu *get_current_percpu(void);
void set_current_percpu(struct percpu *base);
unsigned long get_fs_base(void);

#endif