#include <sys/mman.h>
#define _GNU_SOURCE
#include <stddef.h>
#include <sys/syscall.h>
#include <errno.h>

#include "vmpl-dev.h"
#include "log.h"
#include "fpu.h"
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
#include "platform.h"

struct dune_percpu {
	struct percpu percpu;
	struct fpu_area *fpu;
};

#define to_dune_percpu(percpu_ptr) container_of(percpu_ptr, struct dune_percpu, percpu)

// FPU Routines

static int fpu_init(struct percpu *base)
{
    log_info("fpu init");
    struct dune_percpu *percpu = to_dune_percpu(base);
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

static int fpu_finish(struct percpu *base)
{
    struct dune_percpu *percpu = to_dune_percpu(base);

    dune_fpu_load(percpu->fpu);

    log_info("fpu finish");
    return 0;
}

// PerCPU Level Routines

static struct percpu *dune_percpu_alloc(void)
{
    struct dune_percpu *percpu = (struct dune_percpu *)create_percpu();
    if (!percpu) {
        return NULL;
    }

    return &percpu->percpu;
}

static int dune_percpu_free(struct percpu *base)
{
    struct dune_percpu *percpu = to_dune_percpu(base);
    free_percpu(base);
	munmap(percpu, PGSIZE);
    return 0;
}

static void dune_percpu_dump(struct percpu *base)
{
    struct dune_percpu *percpu = to_dune_percpu(base);
    dump_percpu(base);
	dune_fpu_dump(percpu->fpu);
}

static int dune_percpu_init(struct percpu *base)
{
	int rc;
	unsigned long fs_base;
	struct dune_percpu *percpu = to_dune_percpu(base);

    log_info("dune before enter");

	// map the safe stack
	map_ptr(base->tss.tss_ist[0], SAFE_STACK_SIZE);
	map_ptr(percpu, sizeof(*percpu));
	map_stack();

	// 设置debug_fd
	set_debug_fd(dune_fd);

    return 0;
}

static int dune_percpu_boot(struct percpu *base)
{
	// 启动percpu
	boot_percpu(base);

	return 0;
}

static int do_dune_enter(struct percpu *base)
{
	struct dune_config *conf;
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

// Platform Level Routines

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

static int dune_prepare(bool map_full)
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

	if ((ret = setup_syscall())) {
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
    .alloc = dune_percpu_alloc,
    .free = dune_percpu_free,
    .init = dune_percpu_init,
    .enter = do_dune_enter,
    .boot = dune_percpu_boot,
    .dump = dune_percpu_dump,
    .fpu_init = fpu_init,
    .fpu_finish = fpu_finish,
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

// 使用宏注册DUNE驱动
DECLARE_VM_DRIVER(dune, VM_PLATFORM_INTEL_VTX, &dune_ops);

