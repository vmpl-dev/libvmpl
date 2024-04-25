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
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/syscall.h>

#include "config.h"
#include "percpu.h"
#include "sys.h"
#include "apic.h"
#include "vmpl-dev.h"
#include "ioctl.h"
#include "vmpl.h"
#include "mm.h"
#include "signals.h"
#include "syscall.h"
#include "seimi.h"
#include "log.h"
#include "debug.h"

#define BUILD_ASSERT(cond) _Static_assert(cond, #cond)

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
BUILD_ASSERT(DUNE_PERCPU_GHCB == offsetof(struct dune_percpu, ghcb));
BUILD_ASSERT(DUNE_PERCPU_HOTCALL == offsetof(struct dune_percpu, hotcall));

int dune_fd;

static __thread struct dune_percpu *percpu;

int vmpl_init(bool map_full)
{
    int rc;
    int vmpl_fd;

    log_init();
    log_info("vmpl_init");

    vmpl_fd = open("/dev/" RUN_VMPL_DEV_NAME, O_RDWR);
    if (vmpl_fd == -1) {
        perror("Failed to open /dev/" RUN_VMPL_DEV_NAME);
        rc = -errno;
        goto failed;
    }

    dune_fd = vmpl_ioctl_create_vm(vmpl_fd);
    if (dune_fd < 0) {
        log_err("dune: failed to create vm");
        rc = -errno;
        goto failed;
    }

	if ((rc = setup_mm())) {
        log_err("dune: unable to setup memory management");
        goto failed;
    }

    if ((rc = setup_seimi(dune_fd))) {
		log_err("dune: unable to setup SEIMI");
		goto failed;
	}

    if ((rc = setup_syscall(map_full))) {
        log_err("dune: unable to setup syscall handler");
        goto failed;
    }

    setup_hotcalls();

    setup_signal();

    setup_idt();

    if ((rc = apic_setup())) {
        perror("dune: failed to setup APIC");
		rc = -ENOMEM;
        goto failed_apic;
	}

    return 0;
failed_apic:
	apic_cleanup();
failed:
    close(dune_fd);
    return rc;
}

static void vmpl_init_exit(void)
{
    log_info("vmpl_init_exit");
    vmpl_mm_exit(&vmpl_mm);
    apic_cleanup();
}

#ifdef CONFIG_DUMP_DETAILS
static void vmpl_init_stats(void)
{
    log_info("VMPL Stats:");
    vmpl_mm_stats(&vmpl_mm);
}
#else
static inline void vmpl_init_stats(void) { }
#endif

#ifdef CONFIG_VMPL_TEST
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

int vmpl_enter(int argc, char *argv[])
{
    int rc;
    struct dune_percpu *__percpu;

	log_info("vmpl_enter");

    if (!percpu) {
        __percpu = vmpl_alloc_percpu();
        if (!__percpu) {
            rc = -ENOMEM;
            log_err("dune: failed to allocate percpu struct");
            goto failed;
        }
    } else {
        __percpu = percpu;
        log_debug("dune: fork case");
    }

    rc = do_dune_enter(__percpu);
    if (rc != 0) {
        goto failed;
    }

    vmpl_init_test();
    vmpl_init_banner();
    vmpl_init_stats();

    percpu = __percpu;
    return 0;
failed:
    log_err("dune: failed to enter VMPL mode");
    return rc;
}

void on_dune_syscall(struct dune_config *conf)
{
    conf->rax = syscall(conf->status, conf->rdi, conf->rsi, conf->rdx, conf->r10, conf->r8, conf->r9);
    __dune_go_dune(percpu->vcpu_fd, conf);
}

/**
 * on_dune_exit - handle Dune exits
 *
 * This function must not return. It can either exit(), __dune_go_dune() or
 * __dune_go_linux().
 */
void on_dune_exit(struct dune_config *conf)
{
    switch (conf->ret) {
    case DUNE_RET_EXIT:
        syscall(SYS_exit, conf->status);
        break;
    case DUNE_RET_SYSCALL:
        on_dune_syscall(conf);
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