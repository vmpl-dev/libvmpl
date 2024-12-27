#define _GNU_SOURCE
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <x86intrin.h>

#include "vmpl-dev.h"
#include "config.h"
#include "error.h"
#include "log.h"
#include "sys.h"
#include "idt.h"
#include "signals.h"
#include "syscall.h"
#include "ioctl.h"
#include "mm.h"
#include "seimi.h"
#include "ghcb.h"
#include "percpu.h"
#include "entry.h"
#include "vmpl.h"
#include "serial.h"
#include "ghcb.h"
#include "vc.h"
#include "debug.h"
#include "fpu.h"
#include "percpu.h"
#include "platform.h"

struct vmpl_percpu {
    struct percpu percpu;
    struct Ghcb *ghcb;
    hotcall_t hotcall;
    uint64_t vmpl;
    struct fpu_area *fpu;
    char *xsave_area;
    uint64_t xsave_mask;
    int pkey;
    int vcpu_fd;
} __attribute__((packed));

#define to_vmpl_percpu(percpu_ptr) container_of(percpu_ptr, struct vmpl_percpu, percpu)

const uint64_t GHCB = offsetof(struct vmpl_percpu, ghcb);
const uint64_t HOTCALL = offsetof(struct vmpl_percpu, hotcall);

#define VMPL_PERCPU_GHCB 216
#define VMPL_PERCPU_HOTCALL 224

// PerCPU Level Routines

static int create_vcpu(struct vmpl_percpu *percpu)
{
    int rc;
    struct vcpu_config *config;
    log_info("vcpu create");

    config = vcpu_config_alloc(&percpu->percpu);
    rc = vmpl_ioctl_create_vcpu(dune_fd, config);
    if (rc < 0) {
        vmpl_set_last_error(VMPL_ERROR_DEVICE_NOT_FOUND);
        goto failed;
    }

    int vcpu_fd = rc;
    rc = vmpl_ioctl_set_config(vcpu_fd, config);
    if (rc != 0) {
        vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
        goto failed;
    }

    percpu->vcpu_fd = vcpu_fd;
    free(config);
    return 0;
failed:
    return rc;
}

// FPU Routines

static int fpu_init(struct percpu *base)
{
    log_info("fpu init");
    struct vmpl_percpu *percpu = to_vmpl_percpu(base);
    percpu->xsave_mask = _xgetbv(0);
    
    // 检查 percpu 是否有效
    if (!percpu) {
        log_err("Invalid percpu pointer\n");
        return -EINVAL;
    }

    // 使用 posix_memalign 分配对齐的内存
    void *xsave_area = NULL;
    if (posix_memalign(&xsave_area, 64, 4096)) {
        log_err("Failed to allocate aligned FPU state memory\n");
        return -ENOMEM;
    }
    percpu->xsave_area = xsave_area;

    // 确保 FPU 状态区域已分配并对齐
    if (!percpu->xsave_area || ((uintptr_t)percpu->xsave_area & 0x3F)) {
        log_err("FPU state not properly allocated or aligned\n");
        return -EINVAL;
    }

    // 清零 FPU 状态区域
    memset(percpu->xsave_area, 0, 4096);

    // 初始化 FPU
    asm volatile("fninit");

    // 保存 FPU 状态
    _xsave64(percpu->xsave_area, percpu->xsave_mask);
    return 0;
}

static int fpu_finish(struct percpu *base)
{
    struct vmpl_percpu *percpu = to_vmpl_percpu(base);

    // Restore the XSAVE state
    _xsetbv(0, percpu->xsave_mask);
    _xrstor64(percpu->xsave_area, percpu->xsave_mask);

    // Free the XSAVE area
    free(percpu->xsave_area);
    percpu->xsave_area = NULL;

    log_info("fpu finish");
    return 0;
}

#ifdef CONFIG_VMPL_GHCB
Ghcb *setup_ghcb(int dune_fd)
{
    int rc;
    Ghcb *ghcb;
    log_info("setup ghcb");

    // 映射ghcb, 用于hypercall
    ghcb = mmap((void *)GHCB_MMAP_BASE, PAGE_SIZE, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_FIXED | MAP_POPULATE, dune_fd, 0);
    if (ghcb == MAP_FAILED) {
        perror("dune: failed to map GHCB");
        errno = -ENOMEM;
        goto failed;
    }

    // 设置ghcb, 用于hypercall, 详见AMD APM Vol. 2 15.31
    log_debug("dune: GHCB at %p", ghcb);
    memset(ghcb, 0, sizeof(*ghcb));
    ghcb_set_version(ghcb, GHCB_PROTOCOL_MIN);
    ghcb_set_usage(ghcb, GHCB_DEFAULT_USAGE);
    ghcb_set_sw_exit_code(ghcb, GHCB_NAE_RUN_VMPL);
    ghcb_set_sw_exit_info_1(ghcb, 0);
    ghcb_set_sw_exit_info_2(ghcb, 0);

    return ghcb;
failed:
    return NULL;
}

int vc_init(struct vmpl_percpu *percpu) {
    Ghcb *ghcb_va;
    PhysAddr ghcb_pa;
    log_info("setup GHCB");
    ghcb_va = setup_ghcb(dune_fd);
    if (!ghcb_va) {
        log_err("failed to setup GHCB");
        return -1;
    }

    log_info("setup VC");

	ghcb_pa = (PhysAddr)pgtable_va_to_pa((VirtAddr)ghcb_va);
    log_debug("ghcb_pa: %lx", ghcb_pa);

    vc_establish_protocol();
    vc_register_ghcb(ghcb_pa);
    vc_set_ghcb(ghcb_va);

    percpu->ghcb = ghcb_va;
    return 0;
}

int vc_init_percpu(struct vmpl_percpu *percpu)
{
    Ghcb *ghcb_va;
    pte_t *ptep;
    PhysAddr ghcb_pa;
    uint64_t value;

    // Save original GHCB page address
    ghcb_va = percpu->ghcb;
    // Switch to the default MSR protocol
    percpu->ghcb = NULL;

    // Look up the page table entry for the faulting address
    if (pgtable_lookup(pgroot, ghcb_va, CREATE_NONE, &ptep) != 0)
        goto failed;

    // Obtain physical address of the page
    ghcb_pa = pte_addr(*ptep);
    // Read the GHCB page and check if it is valid
    rdmsrl(MSR_AMD64_SEV_ES_GHCB, value);
    /// If the GHCB page is not registered, register it
    if (value == ghcb_pa)
        goto restore_ghcb;

    // Register the GHCB page
    vc_register_ghcb(ghcb_pa);
restore_ghcb:
    // Set the RW permission for the GHCB page
    *ptep |= PTE_W;
    // Invalidate the TLB entry for the GHCB page
	vmpl_flush_tlb_one(ghcb_va);
    // Restore the percpu GHCB page address
    percpu->ghcb = (void *)ghcb_pa;
    // The GHCB page is valid, return success
    return 0;
failed:
    // The GHCB page is not valid, terminate the VMPL with an error
    return -1;
}
#else
static inline int vc_init(struct vmpl_percpu *percpu) { return 0; }
static inline int vc_init_percpu(struct vmpl_percpu *percpu) { return 0; }
#endif

#ifdef CONFIG_VMPL_HOTCALLS
void hotcalls_enable(struct vmpl_percpu *percpu)
{
	percpu->hotcall = exec_hotcall;
}
#else
static inline void hotcalls_enable(struct vmpl_percpu *percpu) {
	percpu->hotcall = NULL;
}
#endif

static int get_current_vmpl(void)
{
    FILE *fp;
    char line[256];
    int vmpl = -1;

    fp = fopen("/proc/vmpl_proc", "r");
    if (!fp) {
        log_err("Failed to open /proc/vmpl_proc");
        return -errno;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "  Current VMPL: %d\n", &vmpl) == 1) {
            break;
        }
    }

    fclose(fp);
    return vmpl;
}

// PerCPU Level Routines

static struct percpu *vmpl_percpu_alloc(void)
{
    struct vmpl_percpu *percpu = (struct vmpl_percpu *)create_percpu();
    if (!percpu) {
        return NULL;
    }
    return &percpu->percpu;
}

static int vmpl_percpu_free(struct percpu *base)
{
    struct vmpl_percpu *percpu = to_vmpl_percpu(base);
    free(percpu);
    return 0;
}

static void vmpl_percpu_dump(struct percpu *base)
{
    struct vmpl_percpu *percpu = to_vmpl_percpu(base);
    dump_percpu(base);
    dump_ghcb(percpu->ghcb);
    log_debug("hotcall: %p", percpu->hotcall);
    log_debug("vmpl: %lx", percpu->vmpl);
    log_debug("fpu: %p", percpu->fpu);
    log_debug("xsave_area: %p", percpu->xsave_area);
    log_debug("xsave_mask: %lx", percpu->xsave_mask);
    log_debug("pkey: %d", percpu->pkey);
    log_debug("vcpu_fd: %d", percpu->vcpu_fd);
}

static int vmpl_percpu_init(struct percpu *base)
{
    int rc;
    unsigned long fs_base;
    struct vmpl_percpu *percpu = to_vmpl_percpu(base);

    log_debug("vmpl percpu init");

    percpu->ghcb = NULL;
    percpu->hotcall = NULL;
    percpu->vmpl = get_current_vmpl();

    // Setup CPU set for the thread
    if ((rc = setup_cpuset())) {
        vmpl_set_last_error(VMPL_ERROR_RESOURCE_BUSY);
        goto failed;
    }

    // Setup segments registers
    if ((rc = create_vcpu(percpu))) {
        vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
        goto failed;
    }

    // 设置debug_fd
    set_debug_fd(percpu->vcpu_fd);

    return 0;
failed:
    return rc;
}

static int vmpl_percpu_boot(struct percpu *base)
{
    struct vmpl_percpu *percpu = to_vmpl_percpu(base);

    // Setup VC communication
    vc_init(percpu);

    // Setup hotcall
    hotcalls_enable(percpu);

    // Setup serial port
    serial_init();

    return 0;
}

static int do_vmpl_enter(struct percpu *base)
{
    int rc;
    struct vmpl_percpu *percpu = to_vmpl_percpu(base);
    struct dune_config *config = malloc(sizeof(struct dune_config));
    if (!config) {
        vmpl_set_last_error(VMPL_ERROR_OUT_OF_MEMORY);
        return -ENOMEM;
    }

    memset(config, 0, sizeof(struct dune_config));
    /* NOTE: We don't setup the general purpose registers because __dune_ret
     * will restore them as they were before the __dune_enter call */

    config->vcpu = 0;
    config->rip = (uint64_t) &__dune_ret;
    config->rsp = 0;
    config->cr3 = (physaddr_t) pgtable_va_to_pa((VirtAddr)pgroot);
    config->rflags = 0x202;

    // Initialize VMPL library
    rc = __dune_enter(percpu->vcpu_fd, config);
    if (rc) {
        vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
        goto failed;
    }

    return 0;
failed:
    free(config);
    return rc;
}

// System Level Routines

static int create_vm(void)
{
    int vmpl_fd;

    vmpl_fd = open("/dev/" RUN_VMPL_DEV_NAME, O_RDWR);
    if (vmpl_fd == -1) {
        vmpl_set_last_error(VMPL_ERROR_IO);
        return -errno;
    }

    dune_fd = vmpl_ioctl_create_vm(vmpl_fd);
    if (dune_fd < 0) {
        vmpl_set_last_error(VMPL_ERROR_DEVICE_NOT_FOUND);
        return -errno;
    }

    close(vmpl_fd);
    return 0;
}

static int vmpl_prepare(bool map_full)
{
    int rc;
    int vmpl_fd;

    BUILD_ASSERT(IOCTL_DUNE_ENTER == DUNE_ENTER);
    BUILD_ASSERT(DUNE_CFG_RET == offsetof(struct dune_config, ret));
    BUILD_ASSERT(DUNE_CFG_RAX == offsetof(struct dune_config, rax));
    BUILD_ASSERT(DUNE_CFG_RBX == offsetof(struct dune_config, rbx));
    BUILD_ASSERT(DUNE_CFG_RCX == offsetof(struct dune_config, rcx));
    BUILD_ASSERT(DUNE_CFG_RDX == offsetof(struct dune_config, rdx));
    BUILD_ASSERT(DUNE_CFG_RSI == offsetof(struct dune_config, rsi));
    BUILD_ASSERT(DUNE_CFG_RDI == offsetof(struct dune_config, rdi));
    BUILD_ASSERT(DUNE_CFG_RSP == offsetof(struct dune_config, rsp));
    BUILD_ASSERT(DUNE_CFG_RBP == offsetof(struct dune_config, rbp));
    BUILD_ASSERT(DUNE_CFG_R8 == offsetof(struct dune_config, r8));
    BUILD_ASSERT(DUNE_CFG_R9 == offsetof(struct dune_config, r9));
    BUILD_ASSERT(DUNE_CFG_R10 == offsetof(struct dune_config, r10));
    BUILD_ASSERT(DUNE_CFG_R11 == offsetof(struct dune_config, r11));
    BUILD_ASSERT(DUNE_CFG_R12 == offsetof(struct dune_config, r12));
    BUILD_ASSERT(DUNE_CFG_R13 == offsetof(struct dune_config, r13));
    BUILD_ASSERT(DUNE_CFG_R14 == offsetof(struct dune_config, r14));
    BUILD_ASSERT(DUNE_CFG_R15 == offsetof(struct dune_config, r15));
    BUILD_ASSERT(DUNE_CFG_RIP == offsetof(struct dune_config, rip));
    BUILD_ASSERT(DUNE_CFG_RFLAGS == offsetof(struct dune_config, rflags));
    BUILD_ASSERT(DUNE_CFG_CR3 == offsetof(struct dune_config, cr3));
    BUILD_ASSERT(DUNE_CFG_STATUS == offsetof(struct dune_config, status));
    BUILD_ASSERT(DUNE_CFG_VCPU == offsetof(struct dune_config, vcpu));
    BUILD_ASSERT(VMPL_PERCPU_GHCB == offsetof(struct vmpl_percpu, ghcb));
    BUILD_ASSERT(VMPL_PERCPU_HOTCALL == offsetof(struct vmpl_percpu, hotcall));

    log_init();
    log_info("vmpl_init");

    // Setup VMPL without error checking
    setup_signal();
    setup_hotcalls();
    setup_idt();

    // 创建虚拟机
    if ((rc = create_vm())) {
        vmpl_set_last_error(VMPL_ERROR_DEVICE_NOT_FOUND);
        return rc;
    }

    // 初始化内存管理
    if ((rc = setup_mm())) {
        vmpl_set_last_error(VMPL_ERROR_OUT_OF_MEMORY);
        goto failed;
    }

    // 初始化SEIMI
    if ((rc = setup_seimi(dune_fd))) {
        vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
        goto failed;
    }

    // 初始化系统调用
    if ((rc = setup_syscall())) {
        vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
        goto failed;
    }

    // 初始化vsyscall
    if ((rc = setup_vsyscall())) {
        vmpl_set_last_error(VMPL_ERROR_INVALID_OPERATION);
        goto failed;
    }

    // 初始化APIC
    if ((rc = apic_setup())) {
        vmpl_set_last_error(VMPL_ERROR_DEVICE_NOT_FOUND);
        goto failed_apic;
    }

    return 0;

failed_apic:
    apic_cleanup();
failed:
    close(dune_fd);
    return rc;
}

static void vmpl_cleanup(void)
{
    log_info("vmpl_exit");
    vmpl_mm_exit(&vmpl_mm);
    apic_cleanup();
}

static void vmpl_stats(void)
{
    log_info("vmpl_stats");
    vmpl_mm_stats(&vmpl_mm);
}

#ifdef CONFIG_VMPL_TEST
static void vmpl_test(void)
{
    log_info("vmpl_test");
    vmpl_mm_test(&vmpl_mm);
}
#else
static inline void vmpl_test(void) { }
#endif

static void vmpl_banner(void)
{
    log_success("**********************************************");
    log_success("*                                            *");
    log_success("*              Welcome to VMPL!              *");
    log_success("*                                            *");
    log_success("**********************************************");
    return 0;
}

static void vmpl_syscall(struct dune_config *conf)
{
    struct vmpl_percpu *percpu = (struct vmpl_percpu *)dune_get_user_fs();
    conf->rax = syscall(conf->status, conf->rdi, conf->rsi, conf->rdx, conf->r10, conf->r8, conf->r9);
    __dune_go_dune(percpu->vcpu_fd, conf);
}

/**
 * vmpl_exit - handle VMPL exits
 *
 * This function must not return. It can either exit(), __dune_go_dune() or
 * __dune_go_linux().
 */
static void vmpl_exit(struct dune_config *conf)
{
    struct vmpl_percpu *percpu = (struct vmpl_percpu *)dune_get_user_fs();
    switch (conf->ret) {
    case DUNE_RET_EXIT:
        syscall(SYS_exit, conf->status);
        break;
    case DUNE_RET_SYSCALL:
        vmpl_syscall(conf);
        break;
    case DUNE_RET_INTERRUPT:
		dune_debug_handle_int(conf);
		printf("dune: exit due to interrupt %lld\n", conf->status);
        break;
    case DUNE_RET_SIGNAL:
        __dune_go_dune(percpu->vcpu_fd, conf);
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

// VCPU操作实现
const static struct vcpu_ops vmpl_vcpu_ops = {
    .alloc = vmpl_percpu_alloc,
    .free = vmpl_percpu_free,
    .init = vmpl_percpu_init,
    .enter = do_vmpl_enter,
    .boot = vmpl_percpu_boot,
    .dump = vmpl_percpu_dump,
    .fpu_init = fpu_init,
    .fpu_finish = fpu_finish,
};

// VMPL平台操作实现
const static struct vm_ops vmpl_ops = {
    .name = "VMPL (AMD SEV-SNP)",
    .init = vmpl_prepare,
    .cleanup = vmpl_cleanup,
    .exit = vmpl_exit,
    .banner = vmpl_banner,
    .syscall = vmpl_syscall,
    .stats = vmpl_stats,
    .test = vmpl_test,
    .vcpu_ops = vmpl_vcpu_ops,
};

// 使用宏注册VMPL驱动
DECLARE_VM_DRIVER(vmpl, VM_PLATFORM_AMD_SEV, &vmpl_ops);