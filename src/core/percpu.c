#define _GNU_SOURCE
#include <x86intrin.h>
#include <sched.h>
#include <syscall.h>
#include <sys/syscall.h>

#include "vmpl-dev.h"
#include "idt.h"
#include "fpu.h"
#include "vc.h"
#include "serial.h"
#include "log.h"
#include "percpu.h"
#include "debug.h"

static __thread struct percpu *lpercpu = NULL;

const uint64_t TMP = offsetof(struct percpu, tmp);
const uint64_t UFS_BASE = offsetof(struct percpu, ufs_base);
const uint64_t KFS_BASE = offsetof(struct percpu, kfs_base);
const uint64_t IN_USERMODE = offsetof(struct percpu, in_usermode);

unsigned long dune_get_user_fs(void)
{
	void *ptr;
	asm("movq %%gs:(%1), %0" : "=r"(ptr) : "r"(UFS_BASE) : "memory");
	return (unsigned long) ptr;
}

void dune_set_user_fs(unsigned long fs_base)
{
	asm ("movq %0, %%gs:(%1)" : : "r"(fs_base), "r"(UFS_BASE));
}

#ifdef CONFIG_VMPL_CPUSET
static int get_cpu_count()
{
    int rc;
    long nprocs;
    log_debug("get cpu count");

    nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs < 0) {
        perror("dune: failed to get cpu count");
        rc = -EINVAL;
        goto failed;
    }

    log_debug("dune: %ld cpus online", nprocs);
    return nprocs;
failed:
    return rc;
}

static int alloc_cpu()
{
	static int current_cpu = 0;
	static int cpu_count = 0;
    log_debug("alloc cpu");
    if (current_cpu == 0) {
        current_cpu = sched_getcpu();
	}
    if (cpu_count == 0) {
        cpu_count = get_cpu_count();
        assert(cpu_count > 0);
    }

	current_cpu = (current_cpu + 1) % cpu_count;
	int cpu = current_cpu;
	return cpu;
}

int setup_cpuset()
{
    int cpu;
    cpu_set_t cpuset;

    log_info("setup cpuset");

    cpu = alloc_cpu();
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == -1) {
        perror("sched_setaffinity");
        return 1;
    }

    log_debug("dune: running on CPU %d", cpu);
    log_info("Thread %d bound to CPU %d", gettid(), cpu);

    return 0;
}
#endif

static uint64_t gdt_template[NR_GDT_ENTRIES] = {
    0,
    KERNEL_CODE32,
    KERNEL_CODE64,
    KERNEL_DATA,
    USER_CODE32,
    USER_DATA,
    USER_CODE64,
    TSS,
    TSS2,
};

static void setup_gdt(uint64_t *gdt, struct Tss *tss)
{
    log_info("setup gdt");
	memcpy(gdt, gdt_template, sizeof(uint64_t) * NR_GDT_ENTRIES);
    gdt[GD_TSS >> 3] = (SEG_TSSA | SEG_P | SEG_A | SEG_BASELO(tss) | SEG_LIM(sizeof(struct Tss) - 1));
    gdt[GD_TSS2 >> 3] = SEG_BASEHI(tss);
}

static void dump_gdt(uint64_t *gdt)
{
    log_debug("GDT Entries:");
    for (int i = 0; i < NR_GDT_ENTRIES; i++)
    {
        struct gdtr_entry *e = (struct gdtr_entry *)&gdt[i];
        log_debug("GDT Entry[%d]: %016lx", i, gdt[i]);
        log_debug("  Limit: 0x%04lx%04lx  Base:  0x%08lx",
                    e->limit_hi, e->limit_lo, e->base);
        log_debug("  [G-DB-L-AVL P-DPL-S Type]: %lx-%lx-%lx-%lx %lx-%02lx-%lx %lx",
                    e->g, e->db, e->l, e->avl, e->p, e->dpl, e->s, e->type);
    }
}

static void dump_tss(struct Tss *tss)
{
    log_debug("TSS RSP Entries:");
    for (int i = 0; i < 3; i++)
    {
        log_debug("RSP[%d]: %lx", i, tss->tss_rsp[i]);
    }
    log_debug("TSS IST Entries:");
    for (int i = 0; i < 7; i++)
    {
        log_debug("IST[%d]: %lx", i, tss->tss_ist[i]);
    }
    log_debug("IOMB: %x, IOPB: %x", tss->tss_iomb, tss->tss_iopb);
}

static int setup_safe_stack(struct Tss *tss)
{
	int i;
	char *safe_stack;

	log_info("setup safe stack");
	safe_stack = mmap(NULL, SAFE_STACK_SIZE, PROT_READ | PROT_WRITE,
					  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (safe_stack == MAP_FAILED)
		return -ENOMEM;

	safe_stack += SAFE_STACK_SIZE;
	tss->tss_iomb = offsetof(struct Tss, tss_iopb);

	for (i = 0; i < 7; i++)
		tss->tss_ist[i] = (uintptr_t)safe_stack;

	/* changed later on jump to G3 */
	tss->tss_rsp[0] = (uintptr_t)safe_stack;

	return 0;
}

static int free_safe_stack(struct Tss *tss)
{
    munmap(tss->tss_ist[0], SAFE_STACK_SIZE);
    return 0;
}

void *create_percpu(void)
{
    log_debug("create percpu");
	void *percpu = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (percpu == MAP_FAILED)
		return NULL;
    return percpu;
}

int init_percpu(struct percpu *base)
{
    int rc;
    unsigned long fs_base;

    if ((rc = setup_safe_stack(&base->tss))) {
		log_err("dune: failed to setup safe stack");
		return rc;
	}

	fs_base = get_fs_base();
	base->kfs_base = fs_base;
	base->ufs_base = fs_base;
	base->in_usermode = 0;

    // Setup GDT for hypercall
    setup_gdt(base->gdt, &base->tss);

    return 0;
}

int free_percpu(struct percpu *base)
{
    free_safe_stack(&base->tss);
    return 0;
}

void dump_percpu(struct percpu *base)
{
    log_debug("PerCpu Entry:");
    log_debug("percpu_ptr: %lx", base->percpu_ptr);
    log_debug("kfs_base: %lx ufs_base: %lx", base->kfs_base, base->ufs_base);
    log_debug("in_usermode: %lx", base->in_usermode);
    log_debug("tss: %p gdt: %p", &base->tss, base->gdt);
#ifdef CONFIG_VMPL_DETAILS
    dump_gdt(base->gdt);
    dump_tss(&base->tss);
#endif
}

struct vcpu_config *vcpu_config_alloc(struct percpu *base)
{
    struct vcpu_config *config = malloc(sizeof(struct vcpu_config));
    memset(config, 0, sizeof(struct vcpu_config));

    config->lstar = (uint64_t)&__dune_syscall;
    config->fs.base = base->kfs_base;
    config->gs.base = (uint64_t)base;

    config->tr.selector = GD_TSS;
    config->tr.base = (uint64_t)&base->tss;
    config->tr.limit = sizeof(base->tss);
    config->tr.attrib = 0x0089; // refer to linux-svsm

    config->gdtr.base = (uint64_t)&base->gdt;
    config->gdtr.limit = sizeof(base->gdt) - 1;

    config->idtr.base = (uint64_t)&idt;
    config->idtr.limit = sizeof(idt) - 1;

    return config;
}

void boot_percpu(struct percpu *base)
{
	struct tptr _idtr, _gdtr;

	_gdtr.base  = (uint64_t) &base->gdt;
	_gdtr.limit = sizeof(base->gdt) - 1;

	_idtr.base = (uint64_t) &idt;
	_idtr.limit = sizeof(idt) - 1;

	asm volatile(
		// STEP 1: load the new GDT
		"lgdt %0\n"

		// STEP 2: initialize data segements
		"mov %1, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%ss\n"

        // STEP 3: long jump into the new code segment
        "mov %2, %%rax\n"
        "pushq %%rax\n"
        "leaq 1f(%%rip),%%rax\n"
        "pushq %%rax\n"
        "lretq\n"
        "1:\n"
        "nop\n"

        // STEP 4: load the task register (for safe stack switching)
        "mov %3, %%ax\n"
        "ltr %%ax\n"

        // STEP 5: load the new IDT and enable interrupts
        "lidt %4\n"
        "sti\n"

		:
		: "m"(_gdtr), "i"(GD_KD), "i"(GD_KT), "i"(GD_TSS), "m"(_idtr)
		: "rax");
	
	// STEP 6: FS and GS require special initialization on 64-bit
	wrmsrl(MSR_FS_BASE, base->kfs_base);
	wrmsrl(MSR_GS_BASE, (unsigned long) base);

    return 0;
}

struct percpu *get_current_percpu(void)
{
    return lpercpu;
}

void set_current_percpu(struct percpu *percpu)
{
    lpercpu = percpu;
}

unsigned long get_fs_base(void)
{
    unsigned long fs_base;
#ifdef __x86_64__
    if (arch_prctl(ARCH_GET_FS, &fs_base) == -1) {
        printf("dune: failed to get FS register\n");
        return -EIO;
    }
#else
    fs_base = rdfsbase();
#endif
    return fs_base;
}