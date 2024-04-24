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
#include "vc.h"
#include "hotcalls.h"
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
    struct fpu_area *fpu;
    char *xsave_area;
    uint64_t xsave_mask;
    int pkey;
    int vcpu_fd;
} __attribute__((packed));

#define ISR_LEN 16
#define SAFE_STACK_SIZE (2048 * 1024)
#define XSAVE_SIZE 4096

void setup_idt(void);
struct dune_percpu *vmpl_alloc_percpu(void);
void vmpl_free_percpu(struct dune_percpu *percpu);
int vmpl_init_percpu(struct dune_percpu *percpu, struct dune_config *config);