/**
 * @file vmpl.c
 * @brief This file contains the implementation of the VMPL library.
 * @author Benshan Mei
 * @date 2023-10-12 20:28:07
 * 
 * The VMPL library provides a virtual memory page locking mechanism for Linux systems.
 * It includes necessary header files such as asm/prctl.h, sys/syscall.h, unistd.h, stdio.h, 
 * stdint.h, errno.h, fcntl.h, signal.h, syscall.h, stdlib.h, string.h, and stddef.h.
 * 
 * @see https://github.com/mbs0221/my-toy/blob/master/libvmpl/src/vmpl.c
 */
#define _GNU_SOURCE
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syscall.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sched.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "config.h"
#include "env.h"
#include "sys.h"
#include "mmu.h"
#include "apic.h"
#include "vmpl-dev.h"
#include "vmpl-ioctl.h"
#include "vmpl.h"
#include "page.h"
#include "pgtable.h"
#include "mm.h"
#include "seimi.h"
#include "vc.h"
#include "serial.h"
#include "log.h"

#define BUILD_ASSERT(cond) do { (void) sizeof(char [1 - 2*!(cond)]); } while(0)
#define XSAVE_SIZE 4096

int dune_fd;

struct dune_percpu {
	uint64_t percpu_ptr;
	uint64_t tmp;
	uint64_t kfs_base;
	uint64_t ufs_base;
	uint64_t in_usermode;
	struct Tss tss;
	uint64_t gdt[NR_GDT_ENTRIES];
    struct Ghcb *ghcb;
    char *xsave_area;
    uint64_t xsave_mask;
    int pkey;
} __attribute__((packed));

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

#define ISR_LEN 16

typedef uint16_t segdesc_t;
typedef uint64_t tssdesc_t;
typedef uint16_t segsel_t;

static struct idtd idt[IDT_ENTRIES];
static __thread struct dune_percpu *percpu;

#ifdef CONFIG_DUMP_DETAILS
/**
 * @brief  Dump GDT Entries
 * @note   
 * @param  *gdt: pointer to GDT
 * @retval None
 */
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

/**
 * @brief  Dump IDT Entries
 * @note   
 * @param  *idt: pointer to IDT
 * @retval None
 */
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

/**
 * @brief  Dump TSS Entries
 * @note   
 * @param  *tss: pointer to TSS
 * @retval None
 */
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

/**
 * @brief  Dump PerCpu Entries
 * @note   
 * @param  *percpu: pointer to PerCpu
 * @retval None
 */
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

/**
 * @brief  Dump VMPL Configs
 * @note   
 * @param  *percpu: pointer to PerCpu
 * @retval None
 */
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

/**
 * Sets up the Global Descriptor Table (GDT) with the appropriate entries.
 * @note Table 3-1. System-Segment and Gate-Descriptor Types—Long Mode
 * @return void
 */
static void setup_gdt(struct dune_percpu *percpu)
{
    log_info("setup gdt");
	memcpy(percpu->gdt, gdt_template, sizeof(uint64_t) * NR_GDT_ENTRIES);
	percpu->gdt[GD_TSS >> 3] =
		(SEG_TSSA | SEG_P | SEG_A | SEG_BASELO(&percpu->tss) |
		 SEG_LIM(sizeof(struct Tss) - 1));
	percpu->gdt[GD_TSS2 >> 3] = SEG_BASEHI(&percpu->tss);
}

/**
 * Sets the address of an IDT entry.
 * 
 * @param id Pointer to the IDT entry.
 * @param addr The address to be set.
 * @return void
 */
static inline void __set_idt_addr(struct idtd *id, phys_addr_t addr)
{       
    id->low    = addr & 0xFFFF;
    id->middle = (addr >> 16) & 0xFFFF;
    id->high   = (addr >> 32) & 0xFFFFFFFF;
}

/**
 * Initializes an IDT entry.
 * 
 * @param id Pointer to the IDT entry to be initialized.
 * @param i The index of the IDT entry.
 * @param isr The address of the interrupt service routine.
 * @return void
 */
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

/**
 * Sets up the Interrupt Descriptor Table (IDT) with the appropriate entries.
 * @note Table 4-6. System-Segment Descriptor Types—Long Mode (continued)
 * @return void
 */
static void setup_idt(void)
{
    uintptr_t isr = (uintptr_t) &__dune_intr;
    log_info("setup idt");

	for (size_t i = 0; i < IDT_ENTRIES; i++) {
        __init_idtd(&idt[i], i, isr + ISR_LEN * i);
	}
}

/**
 * @brief Sets up signal handling for the VMPL library.
 * 
 * This function disables signals until better support is available.
 * 
 * @return void
 */
#ifdef CONFIG_VMPL_SIGNAL
static void setup_signal(void)
{
    size_t i;
    log_info("setup signal");

    // disable signals for now until we have better support
    log_trace("disable signals for now until we have better support");
    for (i = 1; i < 32; i++) {
        struct sigaction sa;

        switch (i) {
        case SIGTSTP:
        case SIGSTOP:
        case SIGKILL:
        case SIGCHLD:
        case SIGINT:
        case SIGTERM:
            continue;
        }

        memset(&sa, 0, sizeof(sa));

        sa.sa_handler = SIG_IGN;

        if (sigaction(i, &sa, NULL) == -1)
            err(1, "sigaction() %d", i);
    }
}
#else
static void setup_signal(void) { }
#endif

/**
 * Sets up the segment registers.
 * 
 * @param percpu Pointer to the percpu struct.
 * @return 0 on success, otherwise an error code.
 */
static int setup_vmsa(struct dune_percpu *percpu, struct vmsa_config *config)
{
    int rc;
    struct vmpl_segs_t *segs = malloc(sizeof(struct vmpl_segs_t));
    memset(segs, 0, sizeof(struct vmpl_segs_t));
    log_info("setup vmsa");

    segs->fs.base = percpu->kfs_base;
    segs->gs.base = (uint64_t)percpu;

    segs->tr.selector = GD_TSS;
    segs->tr.base = &percpu->tss;
    segs->tr.limit = sizeof(percpu->tss);
    segs->tr.attrib = 0x0089; // refer to linux-svsm

    segs->gdtr.base = (uint64_t)&percpu->gdt;
    segs->gdtr.limit = sizeof(percpu->gdt) - 1;

    segs->idtr.base = (uint64_t)&idt;
    segs->idtr.limit = sizeof(idt) - 1;

    rc = vmpl_ioctl_set_segs(dune_fd, segs);
    if (rc != 0) {
        log_err("dune: failed to set segs");
        goto failed;
    }

    free(segs);
    return 0;
failed:
    return rc;
}

/**
 * Sets up the CPU set.
 * 
 * @return 0 on success, otherwise an error code.
 */
#ifdef CONFIG_VMPL_CPUSET
static int get_cpu_count()
{
    int rc;
    long nprocs;
    log_info("get cpu count");

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
    log_info("alloc cpu");
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


/**
 * Sets up the system call handler.
 * @note 用ioctl，将MSR_LSATR指向的虚拟地址空间，重新映射到dune_syscall所在的物理页
 * @param percpu Pointer to the percpu struct.
 * 
 * @return void
 */
#ifdef CONFIG_VMPL_SYSCALL
static int setup_syscall(struct dune_percpu *percpu)
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

    log_info("dune: lstar at %lx", lstar);
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

    return 0;
}
#else
static int setup_syscall(struct dune_percpu *percpu)
{
    log_warn("vmpl-syscall is not supportted");
    return 0;
}
#endif

/**
 * Sets up the vsyscall handler.
 * @note 用ioctl，将vsyscall指向的虚拟地址空间，重新映射到dune_vsyscall所在的物理页
 * @param percpu Pointer to the percpu struct.
 * 
 * @return void
 */
#ifdef CONFIG_VMPL_VSYSCALL
static int setup_vsyscall(struct dune_percpu *percpu)
{
    pte_t *pte;
    log_info("setup vsyscall");
    vmpl_vm_lookup(pgroot, (void *) VSYSCALL_ADDR, CREATE_NORMAL, &pte);
    *pte = PTE_ADDR(pgtable_va_to_pa(&__dune_vsyscall_page)) | PTE_P | PTE_U | PTE_C;

    return 0;
}
#else
static int setup_vsyscall(struct dune_percpu *percpu)
{
    log_warn("vmpl-vsyscall is not supportted");
    return 0;
}
#endif

/**
 * Sets up the GHCB.
 * 
 * @return void
 */
#ifdef CONFIG_VMPL_GHCB
static int setup_ghcb(struct dune_percpu *percpu)
{
    int rc;
    Ghcb *ghcb;
    log_info("setup ghcb");

    // 映射ghcb, 用于hypercall
    ghcb = mmap((void *)GHCB_MMAP_BASE, PAGE_SIZE, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_FIXED, dune_fd, 0);
    if (ghcb == MAP_FAILED) {
        perror("dune: failed to map GHCB");
        rc = -ENOMEM;
        goto failed;
    }

    // 设置ghcb, 用于hypercall, 详见AMD APM Vol. 2 15.31
    log_debug("dune: GHCB at %p", ghcb);
    ghcb->sw_exit_code = GHCB_NAE_RUN_VMPL;
    ghcb->sw_exit_info_1 = RUN_VMPL;
    ghcb->sw_exit_info_2 = 0;

    percpu->ghcb = ghcb;
    return 0;
failed:
    return rc;
}
#else
static int setup_ghcb(struct dune_percpu *percpu) {
    log_warn("setup ghcb not supported");
    return 0;
}
#endif

/**
 * @brief  Setup stack for VMPL library
 * @note   
 * @retval None
 */
static int setup_stack(size_t stack_size)
{
    int rc;
	const rlim_t kStackSize = stack_size;
	struct rlimit rl;
	log_info("setup stack");

    rc = getrlimit(RLIMIT_STACK, &rl);
    if (rc != 0) {
        perror("dune: failed to get stack size");
        goto failed;
    }

    if (rl.rlim_cur < kStackSize) {
        rl.rlim_cur = kStackSize;
        rc = setrlimit(RLIMIT_STACK, &rl);
        if (rc != 0) {
            perror("dune: failed to set stack size");
            goto failed;
        }
    }

    return 0;
failed:
    return rc;
}

static int setup_heap(size_t increase_size)
{
    int rc;
    struct rlimit rl;
    log_info("setup heap");

    rc = getrlimit(RLIMIT_DATA, &rl);
    if (rc != 0) {
        perror("dune: failed to get heap size");
        goto failed;
    }

    rl.rlim_cur += increase_size;
    rc = setrlimit(RLIMIT_DATA, &rl);
    if (rc != 0) {
        perror("dune: failed to set heap size");
        goto failed;
    }

    return 0;
failed:
    return rc;
}

static void vmpl_default_pf_handler(struct dune_tf *tf)
{
    long rc = 0;
    uint64_t addr = read_cr2();
    rc = vmpl_mm_default_pgflt_handler(addr, tf->err);
    if (rc == 0) {
        return;
    }
    
	syscall(ULONG_MAX, T_PF, (unsigned long)tf);
}

static int setup_mm(struct dune_percpu *percpu)
{
    int rc;
    log_info("setup mm");

    // Setup Stack
    rc = setup_stack(CONFIG_VMPL_STACK_SIZE);
    assert(rc == 0);

    // Setup Heap
    rc = setup_heap(CONFIG_VMPL_HEAP_SIZE);
    assert(rc == 0);

    // Setup VMPL VM
    rc = vmpl_mm_init(&vmpl_mm);
    assert(rc == 0);

    // Setup Page Fault Handler
    dune_register_intr_handler(T_PF, vmpl_default_pf_handler);

    return 0;
}

#ifdef CONFIG_VMPL_XSAVE
#define XSAVE_SIZE 4096
#define XCR_XFEATURE_ENABLED_MASK 0x00000000
// The XSAVE instruction requires 64-byte alignment for state buffers
static int xsave_begin(struct dune_percpu *percpu)
{
    log_info("xsave begin");
    unsigned long long mask = 0x07;
    asm volatile (
        "xgetbv"
        : "=a" (mask)
        : "c" (XCR_XFEATURE_ENABLED_MASK)
    );

    log_debug("xsave mask: %llx", mask);
    percpu->xsave_area = memalign(64, XSAVE_SIZE);
    if (!percpu->xsave_area) {
        perror("dune: failed to allocate xsave area");
        return -ENOMEM;
    }

    memset(percpu->xsave_area, 0, XSAVE_SIZE);
    log_debug("xsave area at %lx", percpu->xsave_area);
    asm volatile (
        ".byte 0x48, 0x0f, 0xae, 0x27"
        :
        : "D" (percpu->xsave_area), "a" (mask), "d" (0x00)
        : "memory"
    );

    percpu->xsave_mask = mask;

    return 0;
}

static int xsave_end(struct dune_percpu *percpu)
{
    unsigned long long mask = percpu->xsave_mask;
    asm volatile (
        "xsetbv" // xsetbv instruction
        : // no output
        : "c" (XCR_XFEATURE_ENABLED_MASK), "a" (mask), "d" (mask >> 32)
        : "memory"
    );

    asm volatile (
        ".byte 0x48, 0x0f, 0xae, 0x2f" // xrstor instruction
        :
        : "D" (percpu->xsave_area), "a" (mask), "d" (0x00)
        : "memory"
    );

    free(percpu->xsave_area);
    percpu->xsave_area = NULL;

    log_info("xsave end");
    return 0;
}
#else
static int xsave_begin(struct dune_percpu *percpu) { return 0; }
static int xsave_end(struct dune_percpu *percpu) { return 0; }
#endif

/** 
 * @brief  Dune signal handler registration
 * @note   
 * @retval 0 on success, otherwise an error code.
 */
sighandler_t dune_signal(int sig, sighandler_t cb)
{
    log_info("dune_signal: register signal %d", sig);
	dune_intr_cb x = (dune_intr_cb)cb; /* XXX */

	if (signal(sig, cb) == SIG_ERR)
		return SIG_ERR;

	dune_register_intr_handler(DUNE_SIGNAL_INTR_BASE + sig, x);

	return NULL;
}

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

/**
 * @brief Asserts the offsets of various fields in the vmsa_config struct.
 * 
 * This function asserts that the offsets of various fields in the vmsa_config struct
 * are equal to their corresponding values in the DUNE_ENTER macro. This is done to ensure
 * that the struct is properly aligned and can be used with the Dune library.
 * 
 * @return void
 */
void vmpl_build_assert(void)
{
    log_debug("vmpl_build_assert");
    BUILD_ASSERT(IOCTL_DUNE_ENTER == DUNE_ENTER);
	BUILD_ASSERT(DUNE_CFG_RET == offsetof(struct vmsa_config, ret));
	BUILD_ASSERT(DUNE_CFG_RAX == offsetof(struct vmsa_config, rax));
	BUILD_ASSERT(DUNE_CFG_RBX == offsetof(struct vmsa_config, rbx));
	BUILD_ASSERT(DUNE_CFG_RCX == offsetof(struct vmsa_config, rcx));
	BUILD_ASSERT(DUNE_CFG_RDX == offsetof(struct vmsa_config, rdx));
	BUILD_ASSERT(DUNE_CFG_RSI == offsetof(struct vmsa_config, rsi));
	BUILD_ASSERT(DUNE_CFG_RDI == offsetof(struct vmsa_config, rdi));
	BUILD_ASSERT(DUNE_CFG_RSP == offsetof(struct vmsa_config, rsp));
	BUILD_ASSERT(DUNE_CFG_RBP == offsetof(struct vmsa_config, rbp));
	BUILD_ASSERT(DUNE_CFG_R8 == offsetof(struct vmsa_config, r8));
	BUILD_ASSERT(DUNE_CFG_R9 == offsetof(struct vmsa_config, r9));
	BUILD_ASSERT(DUNE_CFG_R10 == offsetof(struct vmsa_config, r10));
	BUILD_ASSERT(DUNE_CFG_R11 == offsetof(struct vmsa_config, r11));
	BUILD_ASSERT(DUNE_CFG_R12 == offsetof(struct vmsa_config, r12));
	BUILD_ASSERT(DUNE_CFG_R13 == offsetof(struct vmsa_config, r13));
	BUILD_ASSERT(DUNE_CFG_R14 == offsetof(struct vmsa_config, r14));
	BUILD_ASSERT(DUNE_CFG_R15 == offsetof(struct vmsa_config, r15));
	BUILD_ASSERT(DUNE_CFG_RIP == offsetof(struct vmsa_config, rip));
	BUILD_ASSERT(DUNE_CFG_RFLAGS == offsetof(struct vmsa_config, rflags));
	BUILD_ASSERT(DUNE_CFG_CR3 == offsetof(struct vmsa_config, cr3));
	BUILD_ASSERT(DUNE_CFG_STATUS == offsetof(struct vmsa_config, status));
	BUILD_ASSERT(DUNE_CFG_VCPU == offsetof(struct vmsa_config, vcpu));
}

/**
 * Initializes a vmsa_config struct with default values.
 * 
 * @param conf Pointer to the vmsa_config struct to be initialized.
 */
static struct vmsa_config *vmsa_alloc_config()
{
    log_debug("vmsa_alloc_config");
    struct vmsa_config *conf = malloc(sizeof(struct vmsa_config));
    memset(conf, 0, sizeof(struct vmsa_config));

    /* NOTE: We don't setup the general purpose registers because __dune_ret
     * will restore them as they were before the __dune_enter call */
    conf->rip = (uint64_t) &__dune_ret;
    conf->rsp = 0;
    conf->rflags = 0x202;

    return conf;
}

/**
 * Sets up the safe stack for the VMPL library.
 * 
 * @param percpu Pointer to the percpu struct.
 * @return 0 on success, otherwise an error code.
 */
static int setup_safe_stack(struct dune_percpu *percpu)
{
	int i;
	char *safe_stack;

	log_info("setup safe stack");
	safe_stack = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE,
					  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (safe_stack == MAP_FAILED)
		return -ENOMEM;

	safe_stack += PGSIZE;
	percpu->tss.tss_iomb = offsetof(struct Tss, tss_iopb);

	for (i = 0; i < 7; i++)
		percpu->tss.tss_ist[i] = (uintptr_t)safe_stack;

	/* changed later on jump to G3 */
	percpu->tss.tss_rsp[0] = (uintptr_t)safe_stack;

	return 0;
}

/**
 * Allocates the percpu struct for the VMPL library.
 *
 * @return void
 */
static struct dune_percpu *vmpl_alloc_percpu(void)
{
    struct dune_percpu *percpu;
	unsigned long fs_base, gs_base;

    log_debug("vmpl_alloc_percpu");
#ifdef ARCH_GET_FS
	if (arch_prctl(ARCH_GET_FS, &fs_base) == -1) {
		log_err("dune: failed to get FS register");
		return NULL;
	}
    log_debug("dune: FS base at 0x%lx with arch_prctl", fs_base);

    if (arch_prctl(ARCH_GET_GS, &gs_base) == -1) {
        log_err("dune: failed to get GS register");
        return NULL;
    }
    log_debug("dune: GS base at 0x%lx with arch_prctl", gs_base);
#else

    // rdfsbase
    asm volatile("rdfsbase %0" : "=r"(fs_base));
    log_debug("dune: FS base at 0x%lx with rdfsbase", fs_base);

    // rdgsbase
    asm volatile("rdgsbase %0" : "=r"(gs_base));
    log_debug("dune: GS base at 0x%lx with rdgsbase", gs_base);
#endif

	percpu = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (percpu == MAP_FAILED)
		return NULL;

	percpu->kfs_base = fs_base;
	percpu->ufs_base = fs_base;
	percpu->in_usermode = 0;

	if (setup_safe_stack(percpu)) {
        log_err("dune: failed to setup safe stack");
		munmap(percpu, PGSIZE);
        return NULL;
    }

    return percpu;
}

/**
 * Unmaps the percpu struct for the VMPL library.
 *
 * @return void
 */
static void vmpl_free_percpu(struct dune_percpu *percpu)
{
    log_debug("vmpl_free_percpu");
    munmap(percpu, PGSIZE);
}

bool vmpl_initialized = false;
bool vmpl_booted = false;

/**
 * @brief  Initializes the VMPL library.
 * @note   Common initialization for both pre and post
 * @retval 0 on success, otherwise an error code.
 */
static int vmpl_init(void)
{
    int rc;
    if (vmpl_initialized) {
        log_debug("dune: already initialized");
        return 0;
    }

    log_info("vmpl_init");

    // Open dune_fd
    dune_fd = open("/dev/" RUN_VMPL_DEV_NAME, O_RDWR);
    if (dune_fd == -1) {
        perror("Failed to open /dev/" RUN_VMPL_DEV_NAME);
        rc = -errno;
        goto failed;
    }

    // Setup signal
    setup_signal();

    // Setup IDT
    setup_idt();

    // Setup APIC
    rc = apic_setup();
    if (rc != 0) {
        perror("dune: failed to setup APIC");
        goto failed_apic;
    }

    vmpl_initialized = true;
    return 0;
failed_apic:
	apic_cleanup();
failed:
    return rc;
}

/**
 * Initializes the VMPL library before the main program starts.
 * This function sets up VMPL2 access permission, builds assert, sets up signal, and sets up IDT.
 */
static int vmpl_init_pre(struct dune_percpu *percpu, struct vmsa_config *config)
{
    int rc;

    // Setup GDT for hypercall
    setup_gdt(percpu);

    // Setup segments registers
    setup_vmsa(percpu, config);

    // Setup CPU set
    rc = setup_cpuset();
    assert(rc == 0);

    // Setup GHCB for hypercall
    rc = setup_ghcb(percpu);
    assert(rc == 0);

    // Setup SEIMI for Intra-Process Isolation
    rc = setup_seimi(dune_fd);
    assert(rc == 0);

    // Setup Memory Management
	rc = setup_mm(percpu);
    assert(rc == 0);

    // Setup syscall handler
    rc = setup_syscall(percpu);
    assert(rc == 0);

    // Setup vsyscall handler
    rc = setup_vsyscall(percpu);
    assert(rc == 0);

    // Setup XSAVE for FPU
    rc = xsave_begin(percpu);
    assert(rc == 0);

    return 0;
}

/**
 * dune_boot - Brings the user-level OS online
 * @percpu: the thread-local data
 */
#ifdef CONFIG_DUNE_BOOT
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
static int dune_boot(struct dune_percpu *percpu)
{
    return 0;
}
#endif

/**
 * Initializes the VMPL library after the main program has started.
 * This function sets up the necessary system calls for the library to function properly.
 *
 * @return 0 on success, -1 on failure.
 */
static int vmpl_init_post(struct dune_percpu *percpu)
{
    // Setup XSAVE for FPU
    xsave_end(percpu);

    // wrfsbase, wrgsbase
    wrfsbase(percpu->kfs_base);
    wrgsbase((uint64_t)percpu);

    // wrmsr
    wrmsrl(MSR_LSTAR, (uint64_t) &__dune_syscall);

    // Setup VC communication
    vc_init(percpu->ghcb);

    // Setup serial port
    serial_init();

    // Finish setup
    vmpl_booted = true;
    return 0;
}

static void vmpl_init_exit(void)
{
    log_info("vmpl_init_exit");
    vmpl_mm_exit(&vmpl_mm);
    vmpl_free_percpu(percpu);
    apic_cleanup();
}

#ifdef CONFIG_DUMP_DETAILS
static void vmpl_init_stats(void)
{
    log_info("VMPL Stats:");
    vmpl_mm_stats(&vmpl_mm);
}
#else
static void vmpl_init_stats(void) { }
#endif

#ifdef CONFIG_VMPL_TEST
/**
 * Initializes a test for the VMPL library.
 * This function writes a banner to the standard output and exits.
 *
 * @return 0 on success.
 */
static int vmpl_init_test(void)
{
    vmpl_mm_test(&vmpl_mm);
}
#else
static int vmpl_init_test(void) { }
#endif

static void vmpl_init_banner(void)
{
    log_success("**********************************************");
    log_success("*                                            *");
    log_success("*              Welcome to VMPL!              *");
    log_success("*                                            *");
    log_success("**********************************************");
    return 0;
}

/**
 * Initializes the VMPL library and enters the VMPL mode.
 * 
 * @return 0 if successful, otherwise an error code.
 */
int vmpl_enter(int argc, char *argv[])
{
    int rc;
    struct vmsa_config *__conf;
    struct dune_percpu *__percpu;

    log_init();
	log_info("vmpl_enter");

	// Build assert
    vmpl_build_assert();

    // Check if percpu is already allocated
    if (!percpu) {
        // boot case (first time)
        log_debug("dune: boot case");
        rc = vmpl_init();
        if (rc) {
            log_err("dune: failed to initialize VMPL library");
            goto failed;
        }

        // Allocate percpu struct for VMPL library
        __percpu = vmpl_alloc_percpu();
        if (!__percpu) {
            rc = -ENOMEM;
            log_err("dune: failed to allocate percpu struct");
            goto failed;
        }
    } else {
        // fork case (second time)
        __percpu = percpu;
        log_debug("dune: fork case");
    }

    // Allocate config struct for VMPL library
    __conf = vmsa_alloc_config();
    if (!__conf) {
        log_err("dune: failed to allocate config struct");
        rc = -ENOMEM;
        goto failed;
    }

    // Initialize VMPL library before the main program starts
    rc = vmpl_init_pre(__percpu, __conf);
    if (rc) {
        log_err("dune: failed to initialize VMPL library");
        goto failed;
    }

    // Dump configs
    dump_configs(__percpu);

    // Initialize VMPL library
    rc = __dune_enter(dune_fd, __conf);
    if (rc) {
        perror("dune: entry to Dune mode failed");
        goto failed;
    }

    dune_boot(__percpu);
    vmpl_init_post(__percpu);
    vmpl_init_test();
    vmpl_init_banner();
    vmpl_init_stats();

    percpu = __percpu;
    return 0;

failed:
    log_err("dune: failed to enter Dune mode");
    vmpl_free_percpu(__percpu);
    return -EIO;
}

void on_dune_syscall(struct vmsa_config *conf)
{
    conf->rax = syscall(conf->status, conf->rdi, conf->rsi, conf->rdx, conf->r10, conf->r8, conf->r9);
    __dune_go_dune(dune_fd, conf);
}

/**
 * on_dune_exit - handle Dune exits
 *
 * This function must not return. It can either exit(), __dune_go_dune() or
 * __dune_go_linux().
 */
void on_dune_exit(struct vmsa_config *conf)
{
    switch (conf->ret) {
    case DUNE_RET_EXIT:
        printf("on_dune_exit()\n");
        syscall(SYS_exit, conf->status);
        // exit(conf->status);
    case DUNE_RET_SYSCALL:
        on_dune_syscall(conf);
		break;
    case DUNE_RET_INTERRUPT:
		dune_debug_handle_int(conf);
		printf("dune: exit due to interrupt %lld\n", conf->status);
        break;
    case DUNE_RET_SIGNAL:
        printf("on_dune_exit()\n");
        __dune_go_dune(dune_fd, conf);
        break;
    case DUNE_RET_NOENTER:
        log_warn("dune: re-entry to Dune mode failed, status is %ld", conf->status);
        break;
    default:
        log_warn("dune: unknown exit from Dune, ret=%ld, status=%ld", conf->ret, conf->status);
        break;
    }

    exit(EXIT_FAILURE);
}
