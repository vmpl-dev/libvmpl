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
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <syscall.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef __GLIBC__
#include <sys/mman.h>
#include <sys/resource.h>
#endif

#include "config.h"
#include "env.h"
#include "sys.h"
#include "mmu.h"
#include "apic.h"
#include "vmpl-dev.h"
#include "vmpl.h"
#include "mm.h"
#include "pmm.h"
#include "vc.h"
#include "serial.h"
#include "log.h"

#define BUILD_ASSERT(cond) do { (void) sizeof(char [1 - 2*!(cond)]); } while(0)

static int dune_fd;

struct dune_percpu {
	uint64_t percpu_ptr;
	uint64_t tmp;
	uint64_t kfs_base;
	uint64_t ufs_base;
	uint64_t in_usermode;
	struct Tss tss;
	uint64_t gdt[NR_GDT_ENTRIES];
    uint64_t ghcb_gpa;
    struct Ghcb *ghcb;
    uint64_t *pgd;
    struct pmm *pmm;
    void *lstar;
    void *vsyscall;
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
typedef uintptr_t phys_addr_t;

static struct idtd idt[IDT_ENTRIES];
static __thread struct dune_percpu *percpu;

/**
 * Gets the segment registers.
 * 
 * @param regs Pointer to the vmsa_seg struct to be initialized.
 * @return void
 */
static void get_segment_registers(struct vmsa_config *regs) {
    __asm__ volatile(
        "movw %%cs, %c[cs](%0)\n"
        "movw %%ds, %c[ds](%0)\n"
        "movw %%es, %c[es](%0)\n"
        "movw %%fs, %c[fs](%0)\n"
        "movw %%gs, %c[gs](%0)\n"
        "movw %%ss, %c[ss](%0)\n" ::"r"(regs),
        [cs] "i"(offsetof(struct vmsa_config, cs)),
        [ds] "i"(offsetof(struct vmsa_config, ds)),
        [es] "i"(offsetof(struct vmsa_config, es)),
        [fs] "i"(offsetof(struct vmsa_config, fs)),
        [gs] "i"(offsetof(struct vmsa_config, gs)),
        [ss] "i"(offsetof(struct vmsa_config, ss)));
}

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
    log_debug("ghcb_gpa: %lx ghcb: %p", percpu->ghcb_gpa, percpu->ghcb);
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
#ifdef CONFIG_DUMP_DETAILS
    dump_idt(idt);
    dump_gdt(percpu->gdt);
    dump_tss(&percpu->tss);
#ifdef CONFIG_VMPL_GHCB
    dump_ghcb(percpu->ghcb);
#endif
#endif
    dump_percpu(percpu);
}

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

/**
 * Sets up the segment registers.
 * 
 * @param percpu Pointer to the percpu struct.
 * @return 0 on success, otherwise an error code.
 */
static int setup_vmsa(struct dune_percpu *percpu, struct vmsa_config *config)
{
    log_info("setup vmsa");

    /* NOTE: We don't setup the general purpose registers because __dune_ret
     * will restore them as they were before the __dune_enter call */
    config->rsp = 0;
    config->rflags = 0x2;

    config->cs.base = 0;
    config->cs.selector = GD_KT;
    config->cs.limit = 0xFFFFFFFF;
    config->cs.attrib = 0x029a;

    config->ds.selector = GD_KD;
    config->es = config->ds;
    config->ss = config->ds;

    config->tr.selector = GD_TSS;
    config->tr.base = &percpu->tss;
    config->tr.limit = sizeof(percpu->tss);
    config->tr.attrib = 0x0089; // refer to linux-svsm
    
    config->fs.base = percpu->kfs_base;
    config->gs.base = (uint64_t)percpu;
    config->rip = (uint64_t) &__dune_ret;

    config->gdtr.base = (uint64_t)&percpu->gdt;
    config->gdtr.limit = sizeof(percpu->gdt) - 1;

    config->idtr.base = (uint64_t)&idt;
    config->idtr.limit = sizeof(idt) - 1;

    return 0;
}

/**
 * Sets up the CPU set.
 * 
 * @return 0 on success, otherwise an error code.
 */
static int setup_cpuset()
{
    int cpu;
    cpu_set_t cpuset;

    log_info("setup cpuset");

    cpu = sched_getcpu();
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == -1) {
        perror("sched_setaffinity");
        return 1;
    }

    log_debug("dune: running on CPU %d", cpu);

    return 0;
}

/**
 * Sets up the system call handler.
 * @note 用ioctl，将MSR_LSATR指向的虚拟地址空间，重新映射到dune_syscall所在的物理页
 * @param percpu Pointer to the percpu struct.
 * 
 * @return void
 */
static void setup_syscall(struct dune_percpu *percpu)
{
	uint64_t lstar, vaddr;
	assert((uint64_t) __dune_syscall_end  -
	       (uint64_t) __dune_syscall < PAGE_SIZE);

    log_info("setup syscall");
    lstar = rdmsr(MSR_LSTAR);
    vaddr = PAGE_ALIGN_DOWN(lstar);

#ifdef CONFIG_REMAP_SYSCALL
    // remap syscall page to another page
    percpu->lstar = mremap((void*)vaddr, PAGE_SIZE, PAGE_SIZE, MREMAP_FIXED, NULL);
    if (percpu->lstar == MAP_FAILED) {
        perror("dune: failed to remap syscall page");
        exit(EXIT_FAILURE);
    }
#else
    // unmap syscall page
    munmap(vaddr, PAGE_SIZE);
#endif
    // remap dune syscall page to syscall page
    mremap(__dune_syscall, PAGE_SIZE, PAGE_SIZE, MREMAP_FIXED, vaddr);
}

/**
 * Sets up the vsyscall handler.
 * @note 用ioctl，将vsyscall指向的虚拟地址空间，重新映射到dune_vsyscall所在的物理页
 * @param percpu Pointer to the percpu struct.
 * 
 * @return void
 */
static void setup_vsyscall(struct dune_percpu *percpu)
{
    // 1. 设置vsyscall
    void *vsyscall_addr = (void *)VSYSCALL_ADDR;
    log_info("setup vsyscall");

#ifdef CONFIG_REMAP_VSYSCALL
    // remap vsyscall page to another page
    percpu->vsyscall = mremap(vsyscall_addr, PAGE_SIZE, PAGE_SIZE, MREMAP_FIXED, NULL);
    if (percpu->vsyscall == MAP_FAILED) {
        perror("dune: failed to remap vsyscall page");
        exit(EXIT_FAILURE);
    }
#else
    // unmap vsyscall page
    munmap(vsyscall_addr, PAGE_SIZE);
#endif
    // remap dune vsyscall page to vsyscall page
    mremap(__dune_vsyscall_page, PAGE_SIZE, PAGE_SIZE, MREMAP_FIXED, vsyscall_addr);
}

/**
 * Sets up the GHCB.
 * 
 * @return void
 */
static int setup_ghcb(struct dune_percpu *percpu)
{
    int rc;
    Ghcb *ghcb;
    log_info("setup ghcb");

    // 获取ghcb, 用于hypercall
    rc = ioctl(dune_fd, VMPL_IOCTL_GET_GHCB, &percpu->ghcb_gpa);
    if (rc != 0) {
        perror("dune: failed to get GHCB");
        goto failed;
    }

    log_debug("dune: GHCB_GPA at 0x%lx", percpu->ghcb_gpa);
    // 映射ghcb, 用于hypercall
    ghcb = mmap((void *)GHCB_MMAP_BASE, PAGE_SIZE, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_FIXED, dune_fd, 0);
    if (ghcb == MAP_FAILED) {
        perror("dune: failed to map GHCB");
        goto failed;
    }

    // 设置ghcb, 用于hypercall, 详见AMD APM Vol. 2 15.31
    log_debug("dune: GHCB at %p", ghcb);
#ifdef CONFIG_GHCB_SELFTEST
    ghcb->sw_exit_code = GHCB_NAE_RUN_VMPL;
    ghcb->sw_exit_info_1 = RUN_VMPL;
    ghcb->sw_exit_info_2 = 0;
#endif

    percpu->ghcb = ghcb;
    return 0;
failed:
    return rc;
}

/**
 * Sets up the page table.
 * 
 * @return void
 */
static int setup_pgtable(struct dune_percpu *percpu)
{
    int rc;
    uint64_t cr3;
    log_info("setup pgtable");

    // 获取cr3, 用于hypercall
    rc = ioctl(dune_fd, VMPL_IOCTL_GET_CR3, &cr3);
    if (rc != 0) {
        perror("dune: failed to get CR3");
        goto failed;
    }

    log_debug("dune: CR3 at 0x%lx", cr3);

    rc = pgtable_init(&percpu->pgd, cr3, dune_fd);
    if (rc != 0) {
        perror("dune: failed to setup PGD");
        goto failed;
    }

    log_debug("dune: PGD at %p", percpu->pgd);

#ifdef CONFIG_PGTBALE_SELFTEST
    rc = pgtable_selftest(percpu->pgd, (uint64_t)percpu->pgd);
    if (rc != 0) {
        perror("dune: failed to test pgtable");
        goto failed;
    }

    log_success("pgtable test passed");
#endif

    return 0;
failed:
    return rc;
}

static void vmpl_pf_handler(struct dune_tf *tf)
{
	int rc, level;
	uint64_t cr2 = read_cr2();
	uint64_t pa;
	log_warn("dune: page fault at 0x%016lx, error-code = %x", cr2, tf->err);
	rc = lookup_address(cr2, &level, &pa);
	if (rc != 0) {
		log_err("dune: page fault at unmapped addr 0x%016lx", cr2);
	} else {
		log_warn("dune: page fault at mapped addr 0x%016lx", cr2);
	}

	exit(EXIT_FAILURE);
}

static int setup_pmm(struct dune_percpu *percpu)
{
	int rc;
	uint64_t *pages;
	struct pmm *pmm;
	log_info("setup pmm");

    log_debug("dune: PMM at %p", pmm);
    pages = mmap((void *)PMM_MMAP_BASE, PMM_MMPA_SIZE, PROT_READ | PROT_WRITE,
              MAP_SHARED | MAP_FIXED, dune_fd, 0);

    if (pages == MAP_FAILED) {
        perror("dune: failed to map PMM");
        rc = -ENOMEM;
        goto failed;
    }

    uint64_t order = 9;
    rc = ioctl(dune_fd, VMPL_IOCTL_GET_PAGES, &order);
    if (rc != 0) {
        perror("dune: failed to get pages");
        return rc;
    }

	pmm = pmm_init(pages);
    if (!pmm) {
        perror("dune: failed to setup PMM");
        rc = -ENOMEM;
        goto failed;
    }

    if (pmm_self_test() == 0) {
        perror("dune: failed to test PMM");
        rc = -ENOMEM;
        goto failed;
    }

    percpu->pmm = pmm;
    log_debug("register page fault handler");
    dune_register_pgflt_handler(vmpl_pf_handler);

	return 0;
failed:
    return rc;
}

/**
 * @brief  Setup stack for VMPL library
 * @note   
 * @retval None
 */
static int setup_stack()
{
    int rc;
    const rlim_t kStackSize = BIT(26); // min stack size = 64 MB
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

/**
 * @brief Asserts the offsets of various fields in the vmsa_config struct.
 * 
 * This function asserts that the offsets of various fields in the vmsa_config struct
 * are equal to their corresponding values in the DUNE_ENTER macro. This is done to ensure
 * that the struct is properly aligned and can be used with the Dune library.
 * 
 * @return void
 */
void vmpl_build_assert()
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
static struct dune_percpu *vmpl_alloc_percpu()
{
    struct dune_percpu *percpu;
	unsigned long fs_base;

    log_debug("vmpl_alloc_percpu");
	if (arch_prctl(ARCH_GET_FS, &fs_base) == -1) {
		log_err("dune: failed to get FS register");
		return NULL;
	}

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
static void vmpl_free_percpu()
{
    log_debug("vmpl_free_percpu");
    munmap(percpu, PGSIZE);
}

void vmpl_init_log() {
	const char *log_level_str;
	const char *show_time_str;

    log_level_str = get_env_or_default("VMPL_LOG_LEVEL", "info");
    set_log_level_str(log_level_str);

    show_time_str = get_env_or_default("VMPL_LOG_SHOW_TIME", "false");
    set_show_time(strcmp(show_time_str, "true") == 0);
}

/**
 * @brief  Initializes the VMPL library.
 * @note   Common initialization for both pre and post
 * @retval 0 on success, otherwise an error code.
 */
static int vmpl_init()
{
    int rc;
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

#ifdef CONFIG_VMPL_APIC
    // Setup APIC
    rc = apic_setup();
    if (rc != 0) {
        perror("dune: failed to setup APIC");
        goto failed;
    }
#endif

    return 0;
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
    log_info("vmpl_init_pre");

#ifdef CONFIG_VMPL_CPUSET
    // Setup CPU set
    rc = setup_cpuset();
    if (rc != 0) {
        perror("dune: failed to setup CPU set");
        goto failed;
    }
#endif

    // Setup Stack
    rc = setup_stack();
    if (rc != 0) {
        perror("dune: failed to setup stack");
        goto failed;
    }

#ifdef CONFIG_VMPL_GHCB
    // Setup GHCB for hypercall
    rc = setup_ghcb(percpu);
    if (rc != 0) {
        perror("dune: failed to setup GHCB");
        goto failed;
    }
#endif

    // Setup segments registers
    setup_vmsa(percpu, config);

    // Setup GDT for hypercall
    setup_gdt(percpu);

#ifdef CONFIG_VMPL_PGTABLE
    // Setup pgtable mapping
	rc = setup_pgtable(percpu);
    if (rc != 0) {
        perror("dune: failed to setup pgtable");
        goto failed;
    }

    // Setup pmm
    rc = setup_pmm(percpu);
    if (rc != 0) {
        perror("dune: failed to setup pmm");
        goto failed;
    }
#endif

#ifdef CONFIG_VMPL_SEIMI
    // Setup SEIMI for Intra-Process Isolation
    rc = setup_seimi(dune_fd);
    if (rc != 0) {
        perror("dune: failed to set SEIMI");
        goto failed;
    }
#endif

    return 0;    
failed:
    return rc;
}

/**
 * dune_boot - Brings the user-level OS online
 * @percpu: the thread-local data
 */
static int dune_boot(struct dune_percpu *percpu)
{
	struct tptr _idtr, _gdtr;

    log_info("dune_boot");
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
        "pushq $1f\n"
        "lretq\n"
        "1:\n"
        "nop\n"

        // STEP 4: load the task register (for safe stack switching)
        "mov %3, %%ax\n"
        "ltr %%ax\n"

        // STEP 5: load the new IDT and enable interrupts
        "lidt %4\n"

		:
		: "m"(_gdtr), "i"(GD_KD), "i"(GD_KT), "i"(GD_TSS), "m"(_idtr)
		: "rax");

	return 0;
}

/**
 * Initializes the VMPL library after the main program has started.
 * This function sets up the necessary system calls for the library to function properly.
 *
 * @return 0 on success, -1 on failure.
 */
static int vmpl_init_post(struct dune_percpu *percpu)
{
    // Enable interrupts
    log_info("vmpl_init_post");
    asm volatile("sti\n");

    // Setup FS and GS
    log_info("setup FS and GS");
    wrmsrl(MSR_FS_BASE, percpu->kfs_base);
    wrmsrl(MSR_GS_BASE, (uint64_t)percpu);

#ifdef CONFIG_VMPL_GHCB
    // Setup VC communication
    vc_init(percpu->ghcb_gpa, percpu->ghcb);
#endif

#ifdef CONFIG_SERIAL_PORT
    // Setup serial port
    serial_init();
#endif

#ifdef CONFIG_VMPL_SYSCALL
    // Setup syscall handler
    setup_syscall(percpu);
#endif

#ifdef CONFIG_VMPL_VSYSCALL
    // Setup vsyscall handler
    setup_vsyscall(percpu);
#endif

    return 0;
}

/**
 * Initializes a test for the VMPL library.
 * This function writes a banner to the standard output and exits.
 *
 * @return 0 on success.
 */
static int vmpl_init_test()
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

	// vmpl_init_log();
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

#ifdef CONFIG_DUNE_BOOT
    dune_boot(__percpu);
#endif
    vmpl_init_post(__percpu);
    vmpl_init_test();

    percpu = __percpu;
    return 0;

failed:
    log_err("dune: failed to enter Dune mode");
    vmpl_free_percpu(__percpu);
    return -EIO;
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
		log_warn("dune: exit due to exit(%ld)", conf->status);
        exit(conf->status);
	case DUNE_RET_INTERRUPT:
        // dune_debug_handle_int(conf);
        log_warn("dune: exit due to interrupt %ld", conf->status);
        break;
    case DUNE_RET_SIGNAL:
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
