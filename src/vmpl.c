#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <syscall.h>
#include <stdlib.h>
#include <string.h>

#include "cpu-x86.h"
// #include "svsm-dev.h"
#include "svsm-vmpl.h"
#include "procmap.h"
#include "vmpl.h"
#include "vc.h"

int dune_fd;

static struct idtd idt[IDT_ENTRIES];

void libraryFunction() {
    printf("This is a library function.\\n");
}

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

void grant_vmpl2_access(MemoryMapping *mapping) {
    uint32_t nr_pages;

    switch (get_mapping_type(mapping->pathname)) {
    case PROCMAP_TYPE_UNKNOWN:
    case PROCMAP_TYPE_ANONYMOUS:
    case PROCMAP_TYPE_VSYSCALL:
    case PROCMAP_TYPE_VVAR:
        return;
    default:
        break;
    }

    nr_pages = (mapping->end - mapping->start) >> 12;

    print_mapping_oneline(mapping);
    set_pages_vmpl(mapping->start, RMP_4K, Vmpl2 | VMPL_RWX, nr_pages);
}

static inline void setup_vmpl(void) {
    // 调用解析虚拟地址信息函数并传入回调函数
    parse_proc_maps(grant_vmpl2_access);
}

typedef uintptr_t phys_addr_t;

static inline void set_idt_addr(struct idtd *id, phys_addr_t addr)
{       
    id->low    = addr & 0xFFFF;
    id->middle = (addr >> 16) & 0xFFFF;
    id->high   = (addr >> 32) & 0xFFFFFFFF;
}

#define ISR_LEN 16

static void setup_idt(void)
{
	int i;

    printf("setup idt\n");
	for (i = 0; i < IDT_ENTRIES; i++) {
		struct idtd *id = &idt[i];
		uintptr_t isr = (uintptr_t) &__dune_intr;

		isr += ISR_LEN * i;
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

		set_idt_addr(id, isr);
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

void dune_syscall_handler(struct dune_tf *tf) {

}

void dune_trap_handler(int num, struct dune_tf *tf) {

}

uint64_t call_vmpl1(uint64_t syscall_number, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
	u64 val, resp;
	int ret;

	val = sev_es_rd_ghcb_msr();

	sev_es_wr_ghcb_msr(GHCB_MSR_VMPL_REQ_LEVEL(1));

    // Assuming that syscall_number, arg1, arg2, arg3, arg4, arg5, and arg6 are variables
    unsigned long long result;
    asm volatile(
        "movq %1, %%rax\n" // move the syscall number to RAX register
        "movq %2, %%rdi\n" // move the first argument to RDI register
        "movq %3, %%rsi\n" // move the second argument to RSI register
        "movq %4, %%rdx\n" // move the third argument to RDX register
        "movq %5, %%r10\n" // move the fourth argument to R10 register
        "movq %6, %%r8\n"  // move the fifth argument to R8 register
        "movq %7, %%r9\n"  // move the sixth argument to R9 register
        "rep; vmmcall\n"           // call the syscall
        "movq %%rax, %0\n" // move the return value to result
        : "=r"(result)
        : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6)
        : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9");

    resp = sev_es_rd_ghcb_msr();

	sev_es_wr_ghcb_msr(val);

	if (GHCB_MSR_INFO(resp) != GHCB_MSR_VMPL_RES)
		ret = -EINVAL;

	if (GHCB_MSR_VMPL_RESP_VAL(resp) != 0)
		ret = -EINVAL;

	return ret;
}

int vmpl_init() {
    // Grant VMPL2 access permission
    setup_vmpl();

    // Implementation of vmpl_init function
    printf("Implementation of vmpl_init function\n");

    dune_fd = open("/dev/svsm-vmpl", O_RDWR);
    if (dune_fd == -1)
    {
        perror("Failed to open /dev/svsm-vmpl");
        return 0;
    }

    // Setup IDT
    setup_idt();

    return 0;
}

int vmpl_enter() {
    // Implementation of vmpl_enter function
    printf("Implementation of vmpl_enter function\n");
    struct vmsa_config *conf;
    int ret;

    conf = malloc(sizeof(struct vmsa_config));

    conf->rip = (__u64) &__dune_ret;
    conf->rsp = 0;
    conf->rflags = 0x2;

    /* NOTE: We don't setup the general purpose registers because __dune_ret
        * will restore them as they were before the __dune_enter call */

    ret = __dune_enter(dune_fd, conf);
    if (ret) {
        printf("dune: entry to Dune mode failed, ret is %d\n", ret);
        return -EIO;
    }

    return 0;
}

int vmpl_exit() {
    // Implementation of vmpl_exit function
    printf("Implementation of vmpl_exit function\n");

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
