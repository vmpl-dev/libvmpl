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
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "cpu-x86.h"
#include "mmu.h"
#include "svsm-vmpl.h"
#include "procmap.h"
#include "vmpl.h"
#include "vc.h"
#include "serial.h"
#include "hypercall.h"
#include "utils.h"

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
} __attribute__((packed));

struct gdtr_entry {
    uint64_t limit_lo : 16;     // 段界限低16位
    uint64_t base : 24;         // 
    uint64_t type : 4;
    uint64_t s : 1;
    uint64_t dpl : 2;
    uint64_t p : 1;
    uint64_t limit_hi : 4;
    uint64_t avl : 1;
    uint64_t l : 1;
    uint64_t db : 1;
    uint64_t g : 1;
} __attribute__((packed));

#ifdef __DUNE__
static uint64_t gdt_template[NR_GDT_ENTRIES] = {
	0,
	0,
	SEG64(SEG_X | SEG_R, 0),
	SEG64(SEG_W, 0),
	0,
	SEG64(SEG_W, 3),
	SEG64(SEG_X | SEG_R, 3),
	0,
	0,
};
#else
#define KERNEL_CODE32   0x00cf9b000000ffff // [G], [D], L, AVL, [P], DPL=0, [1], [1], C, [R], [A]
#define KERNEL_CODE64   0x00af9b000000ffff // [G], D, [L], AVL, [P], DPL=0, [1], [1], C, [R], [A]
#define KERNEL_DATA     0x00cf93000000ffff // [G], [B], L, AVL, [P], DPL=0, [1], [0], E, [W], [A]
#define USER_CODE32     0x00cffb000000ffff // [G], [D], L, AVL, [P], DPL=3, [1], [1], C, [R], [A]
#define USER_DATA       0x00cff3000000ffff // [G], [D], L, AVL, [P], DPL=3, [1], [0], E, [W], [A]
#define USER_CODE64     0x00affb000000ffff // [G], D, [L], AVL, [P], DPL=3, [1], [1], C, [R], [A]
#define TSS             0x0080890000000000 // [G], B, L, AVL, [P], DPL=0, [0], [0], [0], [0], [0]
#define TSS2            0x0000000000000000 // [G], B, L, AVL, [P], DPL=0, [0], [0], [0], [0], [0]
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
#endif

#define ISR_LEN 16

typedef uint16_t segdesc_t;
typedef uint64_t tssdesc_t;
typedef uint16_t segsel_t;
typedef uintptr_t phys_addr_t;

static struct idtd idt[IDT_ENTRIES];
static __thread struct dune_percpu *percpu;

#ifdef SETUP_VMPL
/**
 * @brief Set the pages vmpl permission.
 * 
 * @param vaddr The virtual address of the memory mapping.
 * @param rmp_psize The page size of the memory mapping.
 * @param attrs The access permission of the memory mapping.
 * @param nr_pages The number of pages of the memory mapping.
 * 
 * @return void
 */
void set_pages_vmpl(uint64_t vaddr, bool rmp_psize, uint64_t attrs, uint32_t nr_pages)
{
    int fd = open("/dev/svsm-vmpl", O_RDWR);
    if (fd == -1)
    {
        perror("Failed to open /dev/svsm-vmpl");
        return;
    }

    // 设置要传递的数据
    struct vmpl_data data;
    data.gva = vaddr;
    data.page_size = rmp_psize; // RMP_4K;
    data.attrs = attrs;
    data.nr_pages = nr_pages;

    // 调用ioctl向内核传递数据
    if (ioctl(fd, VMPL_IOCTL_SET_DATA, &data) == -1)
    {
        perror("ioctl failed");
        close(fd);
        return;
    }

    // 关闭设备文件
    printf("关闭设备文件\n");
    close(fd);
}

/**
 * Prints a memory mapping on one line.
 * 
 * @param mapping Pointer to the memory mapping to be printed.
 * @return void
 */
void grant_vmpl2_access(MemoryMapping *mapping) {
    uint32_t nr_pages;

    switch (get_mapping_type(mapping->pathname)) {
    // case PROCMAP_TYPE_UNKNOWN:
    // case PROCMAP_TYPE_ANONYMOUS:
    case PROCMAP_TYPE_VSYSCALL: // TOTO: page_vmpl_set: 页面获取失败
    case PROCMAP_TYPE_VVAR: // page_vmpl_set: 页面获取失败
        return;
    default:
        break;
    }

    nr_pages = (mapping->end - mapping->start) >> 12;

    print_mapping_oneline(mapping);

    uint64_t attrs = Vmpl1;
    if (mapping->perms[0] == 'r')
        attrs |= VMPL_R;
    if (mapping->perms[1] == 'w')
        attrs |= VMPL_W;
    if (mapping->perms[2] == 'x')
        attrs |= (VMPL_X_USER | VMPL_X_SUPER);

    set_pages_vmpl(mapping->start, RMP_4K, attrs, nr_pages);
}

/**
 * Sets up VMPL2 access permission.
 * 
 * @return void
 */
static inline void setup_vmpl(void) {
    // 设置vmpl
    printf("setup vmpl\n");
    // 1. 获取当前进程的内存映射
    parse_proc_maps(print_mapping_oneline);
    // 2. 设置vmpl access permission
    parse_proc_maps(grant_vmpl2_access);
}
#endif

/**
 * Gets the segment registers.
 * 
 * @param regs Pointer to the vmsa_seg struct to be initialized.
 * @return void
 */
static void get_segment_registers(struct vmsa_seg *regs) {
    __asm__ volatile(
        "movw %%cs, %c[cs](%0)\n"
        "movw %%ds, %c[ds](%0)\n"
        "movw %%es, %c[es](%0)\n"
        "movw %%fs, %c[fs](%0)\n"
        "movw %%gs, %c[gs](%0)\n"
        "movw %%ss, %c[ss](%0)\n" ::"r"(regs),
        [cs] "i"(offsetof(struct vmsa_seg, cs)),
        [ds] "i"(offsetof(struct vmsa_seg, ds)),
        [es] "i"(offsetof(struct vmsa_seg, es)),
        [fs] "i"(offsetof(struct vmsa_seg, fs)),
        [gs] "i"(offsetof(struct vmsa_seg, gs)),
        [ss] "i"(offsetof(struct vmsa_seg, ss)));
}

/**
 * @brief  Dump GDT Entries
 * @note   
 * @param  *gdt: pointer to GDT
 * @retval None
 */
static void dump_gdt(uint64_t *gdt)
{
    printf("GDT Entries:\n");
    for (int i = 0; i < NR_GDT_ENTRIES; i++)
    {
        struct gdtr_entry *e = (struct gdtr_entry *)&gdt[i];
        printf("GDT Entry[%d]: %016lx", i, gdt[i]);
        printf("  Limit: 0x%04lx%04lx  Base:  0x%08lx",
               e->limit_hi, e->limit_lo, e->base);
        printf("  [G-DB-L-AVL P-DPL-S Type]: %lx-%lx-%lx-%lx %lx-%02lx-%lx %lx\n",
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
    printf("IDT Entries:\n");
    for (int i = 0; i < IDT_ENTRIES; i++)
    {
        struct idtd *id = &idt[i];
        printf("IDT Entry[%d]: %016lx", i, idt[i]);
        printf(" IST: %02x Type: %02x Addr: %08x%04x%04x\n", id->ist, id->type, id->high, id->middle, id->low);
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
    printf("TSS RSP Entries:\n");
    for (int i = 0; i < 3; i++)
    {
        printf("RSP[%d]: %lx\n", i, tss->tss_rsp[i]);
    }
    printf("TSS IST Entries:\n");
    for (int i = 0; i < 7; i++)
    {
        printf("IST[%d]: %lx\n", i, tss->tss_ist[i]);
    }
    printf("IOMB: %x, IOPB: %x\n", tss->tss_iomb, tss->tss_iopb);
}

/**
 * @brief  Dump PerCpu Entries
 * @note   
 * @param  *percpu: pointer to PerCpu
 * @retval None
 */
static void dump_percpu(struct dune_percpu *percpu)
{
    printf("PerCpu Entry:\n");
    printf("percpu_ptr: %lx\n", percpu->percpu_ptr);
    printf("kfs_base: %lx ufs_base: %lx\n", percpu->kfs_base, percpu->ufs_base);
    printf("in_usermode: %lx\n", percpu->in_usermode);
    printf("tss: %p gdt: %p\n", &percpu->tss, percpu->gdt);
    printf("ghcb_gpa: %lx ghcb: %p\n", percpu->ghcb_gpa, percpu->ghcb);
}

/**
 * @brief  Dump VMPL Configs
 * @note   
 * @param  *percpu: pointer to PerCpu
 * @retval None
 */
static void dump_configs(struct dune_percpu *percpu)
{
    dump_idt(idt);
    dump_gdt(percpu->gdt);
    dump_tss(&percpu->tss);
    dump_ghcb(percpu->ghcb);
    dump_percpu(percpu);
}

/**
 * Sets up the Global Descriptor Table (GDT) with the appropriate entries.
 * @note Table 3-1. System-Segment and Gate-Descriptor Types—Long Mode
 * @return void
 */
static void setup_gdt(struct dune_percpu *percpu)
{
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
    case T_BRKPT:
        id->type |= IDTD_CPL3;
        /* fallthrough */
    case T_DBLFLT:
    case T_NMI:
    case T_MCHK:
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
    printf("setup idt\n");

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
    printf("setup signal\n");

    // disable signals for now until we have better support
    printf("disable signals for now until we have better support\n");
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
    printf("setup segs\n");

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

#define VSYSCALL_ADDR 0xffffffffff600000UL

/**
 * Sets up the system call handler.
 * @note 用ioctl，将MSR_LSATR指向的虚拟地址空间，重新映射到dune_syscall所在的物理页
 * 
 * @return void
 */
static void setup_syscall(void)
{
    uint64_t *lstar;
	assert((uint64_t) __dune_syscall_end  -
	       (uint64_t) __dune_syscall < PAGE_SIZE);

    hp_write(STDOUT_FILENO, "setup syscall\n", 14);
    lstar = (void *)native_read_msr(MSR_LSTAR);

#ifdef RESTORE_VMPL0
    // remap syscall page to another page
    hp_mremap(lstar, PAGE_SIZE, PAGE_SIZE, MREMAP_FIXED, NULL);
#else
    // unmap syscall page
    hp_munmap(lstar, PAGE_SIZE);
#endif
    // remap dune syscall page to syscall page
    hp_mremap(__dune_syscall, PAGE_SIZE, PAGE_SIZE, MREMAP_FIXED, lstar);
}

/**
 * Sets up the vsyscall handler.
 * @note 用ioctl，将vsyscall指向的虚拟地址空间，重新映射到dune_vsyscall所在的物理页
 * 
 * @return void
 */
static void setup_vsyscall(void)
{
    // 1. 设置vsyscall
    void *vsyscall_addr = (void *)VSYSCALL_ADDR;
    hp_write(STDOUT_FILENO, "setup vsyscall\n", 15);

#ifdef RESTORE_VMPL0
    // remap vsyscall page to another page
    hp_mremap(vsyscall_addr, PAGE_SIZE, PAGE_SIZE, MREMAP_FIXED, NULL);
#else
    // unmap vsyscall page
    hp_munmap(vsyscall_addr, PAGE_SIZE);
#endif
    // remap dune vsyscall page to vsyscall page
    hp_mremap(__dune_vsyscall_page, PAGE_SIZE, PAGE_SIZE, MREMAP_FIXED, vsyscall_addr);
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
    printf("setup ghcb\n");

    // 获取ghcb, 用于hypercall
    rc = ioctl(dune_fd, VMPL_IOCTL_GET_GHCB, &percpu->ghcb_gpa);
    if (rc != 0) {
        perror("dune: failed to get GHCB");
        goto failed;
    }

    printf("dune: GHCB_GPA at 0x%lx\n", percpu->ghcb_gpa);
    // 映射ghcb, 用于hypercall
    ghcb = mmap((void *)GHCB_MMAP_BASE, PAGE_SIZE, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_FIXED, dune_fd, 0);
    if (ghcb == MAP_FAILED) {
        perror("dune: failed to map GHCB");
        goto failed;
    }

    // 设置ghcb, 用于hypercall, 详见AMD APM Vol. 2 15.31
    printf("dune: GHCB at %p, GHCB_GPA at %lx\n", ghcb, percpu->ghcb_gpa);
    ghcb->sw_exit_code = GHCB_NAE_RUN_VMPL;
    ghcb->sw_exit_info_1 = RUN_VMPL;
    ghcb->sw_exit_info_2 = 0;

    percpu->ghcb = ghcb;
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
    printf("setup stack\n");

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
 * @brief Asserts the offsets of various fields in the vmsa_config struct.
 * 
 * This function asserts that the offsets of various fields in the vmsa_config struct
 * are equal to their corresponding values in the DUNE_ENTER macro. This is done to ensure
 * that the struct is properly aligned and can be used with the Dune library.
 * 
 * @return void
 */
void vmpl_build_assert() {
    printf("IOCTL_DUNE_ENTER = %x, DUNE_ENTER = %lx\n", IOCTL_DUNE_ENTER, DUNE_ENTER);
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
static struct vmsa_config *vmsa_alloc_config() {
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

	if (arch_prctl(ARCH_GET_FS, &fs_base) == -1) {
		printf("dune: failed to get FS register\n");
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
    munmap(percpu, PGSIZE);
}

/**
 * Initializes the VMPL library before the main program starts.
 * This function sets up VMPL2 access permission, builds assert, sets up signal, and sets up IDT.
 */
static int vmpl_init_pre(struct dune_percpu *percpu, struct vmsa_config *config)
{
    int rc;

    // Setup Stack
    rc = setup_stack();
    if (rc != 0) {
        perror("dune: failed to setup stack");
        goto failed;
    }

    printf("vmpl_init_pre\n");
    dune_fd = open("/dev/svsm-vmpl", O_RDWR);
    if (dune_fd == -1) {
        perror("Failed to open /dev/svsm-vmpl");
        rc = -errno;
        goto failed;
    }

    // Setup GHCB for hypercall
    rc = setup_ghcb(percpu);
    if (rc != 0) {
        perror("dune: failed to setup GHCB");
        goto failed;
    }

    // Setup signal
    setup_signal();

    // Setup segments registers
    setup_vmsa(percpu, config);

    // Setup GDT for hypercall
    setup_gdt(percpu);

    // Setup IDT
    setup_idt();

#ifdef SETUP_VMPL
    // Grant VMPL2 access permission
    setup_vmpl();
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
static int vmpl_init_post(struct dune_percpu *percpu, struct vmsa_config *config)
{
    // Enable interrupts
    asm volatile("sti\n");

    // Setup FS and GS
    wrmsrl(MSR_FS_BASE, percpu->kfs_base);
    wrmsrl(MSR_GS_BASE, (uint64_t)percpu);

    // Setup VC communication
    vc_init(percpu->ghcb_gpa, percpu->ghcb);

    // Setup serial port
    // serial_init();

    // Test serial port
    // serial_out("vmpl_init_post\n");

    // Setup syscall handler
    setup_syscall();

    // Setup vsyscall handler
    setup_vsyscall();

    return 0;
}

/**
 * Initializes a test for the VMPL library.
 * This function writes "Hello, World" to the standard output and exits.
 *
 * @return 0 on success.
 */
static int vmpl_init_test() {
    const char *buf = "Hello, World\n";
    hp_write(STDOUT_FILENO, buf, strlen(buf));
    hp_ioctl(dune_fd, DUNE_GET_SYSCALL);
    return 0;
}

/**
 * Initializes the VMPL library and enters the VMPL mode.
 * 
 * @return 0 if successful, otherwise an error code.
 */
int vmpl_enter(int argc, char *argv[]) {
    int rc;
    struct vmsa_config *conf;
    struct dune_percpu *__percpu;

    printf("vmpl_enter\n");

    // Build assert
    vmpl_build_assert();

    // Allocate config struct for VMPL library
    conf = vmsa_alloc_config();
    if (!conf) {
        rc = -ENOMEM;
        goto failed;
    }

    // Check if percpu is already allocated
    if (!percpu) {
        __percpu = vmpl_alloc_percpu();
        if (!__percpu) {
            rc = -ENOMEM;
            goto failed;
        }
        // Initialize VMPL library before the main program starts
        rc = vmpl_init_pre(__percpu, conf);
        if (rc) {
            goto failed;
        }

        // Dump configs
        dump_configs(__percpu);
    }

    // Initialize VMPL library
    rc = __dune_enter(dune_fd, conf);
    if (rc) {
        printf("dune: entry to Dune mode failed, ret is %d\n", rc);
        perror("dune: entry to Dune mode failed");
        goto failed;
    }

    dune_boot(__percpu);
    vmpl_init_post(__percpu, conf);
    vmpl_init_test();

    percpu = __percpu;
    return 0;

failed:
    vmpl_free_percpu();
    return -EIO;
}

/**
 * This function is used to exit the VMPL program.
 * It prints "vmpl_exit" to the console and returns 0.
 *
 * @return 0
 */
int vmpl_exit() {
    vmpl_puts("vmpl_exit\n");
    hp_exit(EXIT_SUCCESS);

    return 0;
}

/**
 * on_dune_exit - handle Dune exits
 *
 * This function must not return. It can either exit(), __dune_go_dune() or
 * __dune_go_linux().
 */
void on_dune_exit(struct vmsa_config *conf) {
    switch (conf->ret) {
    case DUNE_RET_EXIT:
        syscall(SYS_exit, conf->status);
    case DUNE_RET_EPT_VIOLATION:
        printf("dune: exit due to EPT violation\n");
        break;
    case DUNE_RET_INTERRUPT:
        // dune_debug_handle_int(conf);
        printf("dune: exit due to interrupt %lld\n", conf->status);
        break;
    case DUNE_RET_SIGNAL:
        __dune_go_dune(dune_fd, conf);
        break;
    case DUNE_RET_UNHANDLED_VMEXIT:
        printf("dune: exit due to unhandled VM exit\n");
        break;
    case DUNE_RET_NOENTER:
        printf("dune: re-entry to Dune mode failed, status is %lld\n", conf->status);
        break;
    default:
        printf("dune: unknown exit from Dune, ret=%lld, status=%lld\n", conf->ret, conf->status);
        break;
    }

    exit(EXIT_FAILURE);
}
