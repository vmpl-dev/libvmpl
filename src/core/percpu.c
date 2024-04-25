#define _GNU_SOURCE
#include <x86intrin.h>
#include <sched.h>
#include <syscall.h>
#include <sys/syscall.h>

#include "vmpl-dev.h"
#include "fpu.h"
#include "vc.h"
#include "serial.h"
#include "log.h"
#include "percpu.h"

unsigned long dune_get_user_fs(void)
{
	void *ptr;
	asm("movq %%gs:%c[ufs_base], %0" : "=r"(ptr) :
	    [ufs_base]"i"(offsetof(struct dune_percpu, ufs_base)) : "memory");
	return (unsigned long) ptr;
}

void dune_set_user_fs(unsigned long fs_base)
{
	asm ("movq %0, %%gs:%c[ufs_base]" : : "r"(fs_base),
	     [ufs_base]"i"(offsetof(struct dune_percpu, ufs_base)));
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

static int setup_cpuset()
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
#else
static int setup_cpuset()
{
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

static void setup_gdt(struct dune_percpu *percpu)
{
    log_info("setup gdt");
	memcpy(percpu->gdt, gdt_template, sizeof(uint64_t) * NR_GDT_ENTRIES);
    percpu->gdt[GD_TSS >> 3] = (SEG_TSSA | SEG_P | SEG_A | SEG_BASELO(&percpu->tss) | SEG_LIM(sizeof(struct Tss) - 1));
    percpu->gdt[GD_TSS2 >> 3] = SEG_BASEHI(&percpu->tss);
}

static struct idtd idt[IDT_ENTRIES];

static inline void __set_idt_addr(struct idtd *id, phys_addr_t addr)
{
    id->low    = addr & 0xFFFF;
    id->middle = (addr >> 16) & 0xFFFF;
    id->high   = (addr >> 32) & 0xFFFFFFFF;
}

static inline void __init_idtd(struct idtd *id, int i, uintptr_t isr)
{
    memset(id, 0, sizeof(*id));
    id->selector = GD_KT;
    id->type     = IDTD_P | IDTD_TRAP_GATE;
    switch (i) {
    case T_BP:
        id->type |= IDTD_CPL3;
        /* fallthrough */
    case T_DF:
    case T_NMI:
    case T_MC:
        id->ist = 1;
        break;
    }
    __set_idt_addr(id, isr);
}

void setup_idt(void)
{
    uintptr_t isr = (uintptr_t) &__dune_intr;
    log_info("setup idt");

	for (size_t i = 0; i < IDT_ENTRIES; i++) {
        __init_idtd(&idt[i], i, isr + ISR_LEN * i);
	}
}

static int setup_vmsa(struct dune_percpu *percpu)
{
    int rc;
    struct vcpu_config *config = malloc(sizeof(struct vcpu_config));
    memset(config, 0, sizeof(struct vcpu_config));
    log_info("setup vmsa");

    config->lstar = &__dune_syscall;
    config->fs.base = percpu->kfs_base;
    config->gs.base = (uint64_t)percpu;

    config->tr.selector = GD_TSS;
    config->tr.base = &percpu->tss;
    config->tr.limit = sizeof(percpu->tss);
    config->tr.attrib = 0x0089; // refer to linux-svsm

    config->gdtr.base = (uint64_t)&percpu->gdt;
    config->gdtr.limit = sizeof(percpu->gdt) - 1;

    config->idtr.base = (uint64_t)&idt;
    config->idtr.limit = sizeof(idt) - 1;

    rc = vmpl_ioctl_create_vcpu(dune_fd, config);
    if (rc < 0) {
        log_err("dune: failed to create vcpu");
        goto failed;
    }

    int vcpu_fd = rc;
    rc = vmpl_ioctl_set_config(vcpu_fd, config);
    if (rc != 0) {
        log_err("dune: failed to set config");
        goto failed;
    }

    percpu->vcpu_fd = vcpu_fd;
    free(config);
    return 0;
failed:
    return rc;
}

#ifdef CONFIG_DUMP_DETAILS
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

static void dump_idt(struct idtd *idt)
{
    log_debug("IDT Entries:");
    for (int i = 0; i < IDT_ENTRIES; i++)
    {
        struct idtd *id = &idt[i];
        log_debug("IDT Entry[%d]: %016lx", i, idt[i]);
        log_debug(" IST: %02x Type: %02x Addr: %08x%04x%04x", id->ist, id->type, id->high, id->middle, id->low);
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

static void dump_percpu(struct dune_percpu *percpu)
{
    
    log_debug("PerCpu Entry:");
    log_debug("percpu_ptr: %lx", percpu->percpu_ptr);
    log_debug("kfs_base: %lx ufs_base: %lx", percpu->kfs_base, percpu->ufs_base);
    log_debug("in_usermode: %lx", percpu->in_usermode);
    log_debug("tss: %p gdt: %p", &percpu->tss, percpu->gdt);
    log_debug("ghcb: %p", percpu->ghcb);
    log_debug("lstar: %p vsyscall: %p", percpu->lstar, percpu->vsyscall);
}

static void dump_configs(struct dune_percpu *percpu)
{
    log_debug("VMPL Configs:");
    dump_idt(idt);
    dump_gdt(percpu->gdt);
    dump_tss(&percpu->tss);
    dump_ghcb(percpu->ghcb);
    dump_percpu(percpu);
}
#else
static void dump_configs(struct dune_percpu *percpu) {}
#endif

static int setup_safe_stack(struct dune_percpu *percpu)
{
	int i;
	char *safe_stack;

	log_info("setup safe stack");
	safe_stack = mmap(NULL, SAFE_STACK_SIZE, PROT_READ | PROT_WRITE,
					  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (safe_stack == MAP_FAILED)
		return -ENOMEM;

	safe_stack += SAFE_STACK_SIZE;
	percpu->tss.tss_iomb = offsetof(struct Tss, tss_iopb);

	for (i = 0; i < 7; i++)
		percpu->tss.tss_ist[i] = (uintptr_t)safe_stack;

	/* changed later on jump to G3 */
	percpu->tss.tss_rsp[0] = (uintptr_t)safe_stack;

	return 0;
}

struct dune_percpu *vmpl_alloc_percpu(void)
{
    struct dune_percpu *percpu;
	unsigned long fs_base, gs_base;

    log_debug("vmpl_alloc_percpu");
	percpu = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (percpu == MAP_FAILED)
		return NULL;

    fs_base = rdfsbase();
    gs_base = rdgsbase();
	percpu->kfs_base = fs_base;
	percpu->ufs_base = fs_base;
	percpu->in_usermode = 1;
    percpu->ghcb = NULL;
    percpu->hotcall = NULL;

	if (setup_safe_stack(percpu)) {
        log_err("dune: failed to setup safe stack");
		munmap(percpu, PGSIZE);
        return NULL;
    }

    return percpu;
}

void vmpl_free_percpu(struct dune_percpu *percpu)
{
    log_debug("vmpl_free_percpu");
    munmap(percpu, PGSIZE);
}

#ifdef CONFIG_DUNE_BOOT
static int xsave_begin(struct dune_percpu *percpu)
{
    log_info("xsave begin");
    percpu->fpu = memalign(64, sizeof(struct fpu_area));
    if (!percpu->fpu) {
        perror("dune: failed to allocate fpu area");
        return -ENOMEM;
    }

    dune_fpu_init(percpu->fpu);
    dune_fpu_save(percpu->fpu);
    dune_fpu_dump((struct fpu_area *)percpu->xsave_area);
    return 0;
}

static int xsave_end(struct dune_percpu *percpu)
{
    dune_fpu_load(percpu->fpu);

    log_info("xsave end");
    return 0;
}

static int dune_boot(struct dune_percpu *percpu)
{
	struct tptr _idtr, _gdtr;

	_gdtr.base = (uint64_t)&percpu->gdt;
	_gdtr.limit = sizeof(percpu->gdt) - 1;

	_idtr.base = (uint64_t)&idt;
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
    wrmsrl(MSR_FS_BASE, percpu->kfs_base);
    wrmsrl(MSR_GS_BASE, (uint64_t)percpu);

	return 0;
}
#else
static int dune_boot(struct dune_percpu *percpu) { return 0; }

static int xsave_begin(struct dune_percpu *percpu)
{
    log_info("xsave begin");
    percpu->xsave_mask = _xgetbv(0);

    log_debug("xsave mask: %llx", percpu->xsave_mask);
    // The XSAVE instruction requires 64-byte alignment for state buffers
    percpu->xsave_area = memalign(64, XSAVE_SIZE);
    if (!percpu->xsave_area) {
        perror("dune: failed to allocate xsave area");
        return -ENOMEM;
    }

    log_debug("xsave area at %lx", percpu->xsave_area);
    memset(percpu->xsave_area, 0, XSAVE_SIZE);
    _xsave64(percpu->xsave_area, percpu->xsave_mask);

    dune_fpu_dump((struct fpu_area *)percpu->xsave_area);
    return 0;
}

static int xsave_end(struct dune_percpu *percpu)
{
    // Restore the XSAVE state
    _xsetbv(0, percpu->xsave_mask);
    _xrstor64(percpu->xsave_area, percpu->xsave_mask);

    // Free the XSAVE area
    free(percpu->xsave_area);
    percpu->xsave_area = NULL;

    log_info("xsave end");
    return 0;
}
#endif

static int vmpl_init_pre(struct dune_percpu *percpu)
{
    int rc;

    // Setup CPU set for the thread
    if ((rc = setup_cpuset())) {
        log_err("dune: unable to setup CPU set");
        goto failed;
    }

    // Setup GDT for hypercall
    setup_gdt(percpu);

    // Setup segments registers
    if ((rc = setup_vmsa(percpu))) {
		log_err("dune: failed to setup vmsa");
		goto failed;
	}

    // Setup XSAVE for FPU
    if ((rc = xsave_begin(percpu))) {
		log_err("dune: failed to setup xsave");
		goto failed;
	}

    return 0;
failed:
	return rc;
}

static int vmpl_init_post(struct dune_percpu *percpu)
{
    // Now we are in VMPL mode
    percpu->in_usermode = 0;

    // Setup XSAVE for FPU
    xsave_end(percpu);

    // Setup VC communication
    vc_init(percpu);

    // Setup hotcall
    hotcalls_enable(percpu);

    // Setup serial port
    serial_init();

    return 0;
}

static int __do_dune_enter(int vcpu_fd)
{
    int rc;
    struct dune_config *config = malloc(sizeof(struct dune_config));
    if (!config) {
        log_err("dune: failed to allocate config struct");
        return -ENOMEM;
    }

    memset(config, 0, sizeof(struct dune_config));
    /* NOTE: We don't setup the general purpose registers because __dune_ret
     * will restore them as they were before the __dune_enter call */
    config->rip = (uint64_t) &__dune_ret;
    config->rsp = 0;
    config->rflags = 0x202;

    // Initialize VMPL library
    rc = __dune_enter(vcpu_fd, config);
    if (rc) {
        perror("dune: entry to Dune mode failed");
        goto failed;
    }

    return 0;
failed:
    free(config);
    return rc;
}

int do_dune_enter(struct dune_percpu *percpu)
{
    int rc;

    rc = vmpl_init_pre(percpu);
    if (rc) {
        log_err("dune: failed to initialize VMPL library");
        goto failed;
    }

    // Dump configs
    dump_configs(percpu);

    rc = __do_dune_enter(percpu->vcpu_fd);
    if (rc) {
        log_err("dune: failed to enter Dune mode");
        goto failed;
    }

    dune_boot(percpu);
    vmpl_init_post(percpu);

    return 0;
failed:
    log_err("dune: failed to enter Dune mode");
    vmpl_free_percpu(percpu);
    return -EIO;
}