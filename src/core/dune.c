#define _GNU_SOURCE
#include <stddef.h>
#include <sys/syscall.h>
#include <errno.h>

#include "vmpl-dev.h"
#include "log.h"
#include "error.h"
#include "signals.h"
#include "syscall.h"
#include "idt.h"
#include "fpu.h"
#include "layout.h"
#include "mapping.h"
#include "page.h"
#include "percpu.h"
#include "entry.h"
#include "debug.h"
#include "vmpl.h"


struct dune_percpu {
	uint64_t percpu_ptr;
	uint64_t tmp;
	uint64_t kfs_base;
	uint64_t ufs_base;
	uint64_t in_usermode;
	struct Tss tss;
	uint64_t gdt[NR_GDT_ENTRIES];
	struct fpu_area *fpu;
};

#ifdef CONFIG_DUMP_DETAILS
static void dump_percpu(struct dune_percpu *percpu)
{
    log_debug("PerCpu Entry:");
    log_debug("percpu_ptr: %lx", percpu->percpu_ptr);
    log_debug("kfs_base: %lx ufs_base: %lx", percpu->kfs_base, percpu->ufs_base);
    log_debug("in_usermode: %lx", percpu->in_usermode);
    log_debug("tss: %p gdt: %p", &percpu->tss, percpu->gdt);
}

static void dump_configs(struct dune_percpu *percpu)
{
    log_debug("DUNE Configs:");
    dump_idt(idt);
    dump_gdt(percpu->gdt);
    dump_tss(&percpu->tss);
    dump_percpu(percpu);
}
#else
static void dump_configs(struct dune_percpu *percpu) {}
#endif

static int fpu_init(struct dune_percpu *percpu)
{
    log_info("fpu init");
    percpu->fpu = memalign(64, sizeof(struct fpu_area));
    if (!percpu->fpu) {
        vmpl_set_last_error(VMPL_ERROR_OUT_OF_MEMORY);
        log_err("dune: failed to allocate fpu area");
        return -ENOMEM;
    }

    dune_fpu_init(percpu->fpu);
    dune_fpu_save(percpu->fpu);
    dune_fpu_dump(percpu->fpu);
    return 0;
}

static int fpu_finish(struct dune_percpu *percpu)
{
    dune_fpu_load(percpu->fpu);

    log_info("fpu finish");
    return 0;
}

static int dune_percpu_init(void *__percpu)
{
	int rc;
	unsigned long fs_base;
	struct dune_percpu *percpu = (struct dune_percpu *) __percpu;

    log_info("dune before enter");

	if ((rc = setup_safe_stack(&percpu->tss))) {
		vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
		log_err("dune: failed to setup safe stack");
		return rc;
	}

	fs_base = get_fs_base();
	percpu->kfs_base = fs_base;
	percpu->ufs_base = fs_base;
	percpu->in_usermode = 0;

	// map the safe stack
	map_ptr(percpu->tss.tss_ist[0], SAFE_STACK_SIZE);
	map_ptr(percpu, sizeof(*percpu));
	map_stack();

	// 设置debug_fd
	set_debug_fd(dune_fd);

	// 初始化xsave
	rc = fpu_init(percpu);
	if (rc) {
		vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
		log_err("dune: failed to initialize fpu");
		return rc;
	}

    return 0;
}

static int dune_boot(void *__percpu)
{
	struct dune_percpu *percpu = (struct dune_percpu *) __percpu;
	struct tptr _idtr, _gdtr;

	setup_gdt(percpu->gdt, &percpu->tss);

	_gdtr.base  = (uint64_t) &percpu->gdt;
	_gdtr.limit = sizeof(percpu->gdt) - 1;

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
	wrmsrl(MSR_FS_BASE, percpu->kfs_base);
	wrmsrl(MSR_GS_BASE, (unsigned long) percpu);

	// STEP 7: finish fpu
	int rc = fpu_finish(percpu);
	if (rc) {
		vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
		log_err("dune: failed to finish fpu");
		return rc;
	}

	return 0;
}

static int do_dune_enter(void *__percpu)
{
	struct dune_config *conf;
	struct dune_percpu *percpu = (struct dune_percpu *) __percpu;
	int ret;

	conf = malloc(sizeof(struct dune_config));

	conf->vcpu = 0;
	conf->rip = (uint64_t) &__dune_ret;
	conf->rsp = 0;
	conf->cr3 = (physaddr_t) pgroot;
	conf->rflags = 0x2;

	/* NOTE: We don't setup the general purpose registers because __dune_ret
	 * will restore them as they were before the __dune_enter call */

	ret = __dune_enter(dune_fd, conf);
	if (ret) {
		free(conf);
		vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
		return -EIO;
	}

	return 0;
}

static void dune_banner(void)
{
    log_success("**********************************************");
	log_success("*                                            *");
	log_success("*              Welcome to DUNE!              *");
	log_success("*                                            *");
	log_success("**********************************************");
}

static void dune_test(void)
{
    log_info("dune_test");
}

static void dune_stats(void)
{
    log_info("dune stats");

	// 展示DUNE的统计信息
}

static void dune_syscall(struct dune_config *conf)
{
	conf->rax = syscall(conf->status, conf->rdi, conf->rsi, conf->rdx, conf->r10, conf->r8, conf->r9);
	__dune_go_dune(dune_fd, conf);
}

static void dune_cleanup(void)
{
    log_info("dune cleanup");

	apic_cleanup();
}

static void dune_exit(struct dune_config *conf)
{
	switch (conf->ret) {
	case DUNE_RET_EXIT:
		syscall(SYS_exit, conf->status);
		break;
	case DUNE_RET_EPT_VIOLATION:
		printf("dune: exit due to EPT violation\n");
		break;
	case DUNE_RET_INTERRUPT:
		dune_debug_handle_int(conf);
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

int dune_prepare(bool map_full)
{
	int ret, i;

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

	dune_fd = open("/dev/dune", O_RDWR);
	if (dune_fd <= 0) {
		vmpl_set_last_error(VMPL_ERROR_IO);
		log_err("dune: failed to open Dune device");
		ret = -errno;
		goto fail_open;
	}

	pgroot = memalign(PGSIZE, PGSIZE);
	if (!pgroot) {
		ret = -ENOMEM;
		goto fail_pgroot;
	}
	memset(pgroot, 0, PGSIZE);

	if ((ret = dune_page_init())) {
		vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
		log_err("dune: unable to initialize page manager");
		goto err;
	}

	if ((ret = mapping_init(true))) {
		vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
		log_err("dune: unable to initialize address mapping");
		goto err;
	}

	if ((ret = setup_mappings(map_full))) {
		vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
		log_err("dune: unable to setup memory layout");
		goto err;
	}

	if ((ret = setup_syscall(map_full))) {
		vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
		log_err("dune: unable to setup system calls");
		goto err;
	}

	setup_signal();

	setup_idt();
	if ((ret = apic_setup())) {
		vmpl_set_last_error(VMPL_ERROR_INVALID_STATE);
		log_err("dune: could not set up APIC");
		goto err;
	}

	return 0;

err:
	// FIXME: need to free memory
	apic_cleanup();
fail_pgroot:
	close(dune_fd);
fail_open:
	return ret;
}

// VCPU操作实现
static const struct vcpu_ops dune_vcpu_ops = {
    .init = dune_percpu_init,
    .enter = do_dune_enter,
    .boot = dune_boot,
};

// DUNE平台操作实现
static const struct vm_ops dune_ops = {
    .name = "DUNE (Intel VT-x)",
    .init = dune_prepare,
    .exit = dune_exit,
	.banner = dune_banner,
    .syscall = dune_syscall,
    .cleanup = dune_cleanup,
    .stats = dune_stats,
    .test = dune_test,
    .vcpu_ops = dune_vcpu_ops,
};

// 注册DUNE平台操作
const struct vm_ops *register_dune_ops(void) {
    return &dune_ops;
}

