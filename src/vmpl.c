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
// #include "globals.h"
#include "vc.h"
#include "hypercall.h"

#define BUILD_ASSERT(cond) do { (void) sizeof(char [1 - 2*!(cond)]); } while(0)

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
    case PROCMAP_TYPE_VSYSCALL: // TOTO: page_vmpl_set: 页面获取失败
    case PROCMAP_TYPE_VVAR: // page_vmpl_set: 页面获取失败
        return;
    default:
        break;
    }

    nr_pages = (mapping->end - mapping->start) >> 12;

    print_mapping_oneline(mapping);

    uint64_t attrs = Vmpl2;
    if (mapping->perms[0] == 'r')
        attrs |= VMPL_R;
    if (mapping->perms[1] == 'w')
        attrs |= VMPL_W;
    if (mapping->perms[2] == 'x')
        attrs |= VMPL_X_SUPER;

    if (get_mapping_type(mapping->pathname) == PROCMAP_TYPE_VDSO) {
        attrs = VMPL_R | VMPL_X_USER | VMPL_X_SUPER | Vmpl2;
    }

    if (get_mapping_type(mapping->pathname) == PROCMAP_TYPE_VVAR) {
        attrs = VMPL_R | Vmpl2;
    }

    set_pages_vmpl(mapping->start, RMP_4K, attrs, nr_pages);
}

static inline void setup_vmpl(void) {
    // 设置vmpl
    printf("setup vmpl\n");
    //  1. 获取当前进程的内存映射
    parse_proc_maps(grant_vmpl2_access);
}

// 通过内联汇编加载 GDTR
void load_gdtr(uint64_t gdtr_address) {
    asm volatile ("lgdt (%0)" : : "r" (gdtr_address));
}

// 通过内联汇编加载 TR
void load_tr(uint16_t tr_selector) {
    asm volatile ("ltr %0" : : "m" (tr_selector));
}

// 通过内联汇编加载 IDTR
void load_idtr(uint64_t idtr_address) {
    asm volatile ("lidt (%0)" : : "r" (idtr_address));
}

typedef uintptr_t phys_addr_t;

static inline void set_idt_addr(struct idtd *id, phys_addr_t addr)
{       
    id->low    = addr & 0xFFFF;
    id->middle = (addr >> 16) & 0xFFFF;
    id->high   = (addr >> 32) & 0xFFFFFFFF;
}

#define ISR_LEN 16

/**
 * Sets up the Interrupt Descriptor Table (IDT) with the appropriate entries.
 * @note Table 4-6. System-Segment Descriptor Types—Long Mode (continued)
 * @return void
 */
static void setup_idt(void)
{
    // function implementation
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

/**
 * Sets up the system call handler.
 * 
 * @return void
 */
static void setup_syscall(void)
{
    uint64_t *lstar;
    printf("setup syscall\n");

	assert((uint64_t) __dune_syscall_end  -
	       (uint64_t) __dune_syscall < PAGE_SIZE);

    lstar = (void *)native_read_msr(MSR_LSTAR);

    memcpy(lstar, __dune_syscall,
           (uint64_t)__dune_syscall_end -
               (uint64_t)__dune_syscall);
}


/**
 * Sets up the vsyscall handler.
 * 
 * @return void
 */
static void setup_vsyscall(void)
{
    // 1. 设置vsyscall
    void *vsyscall_addr = (void *)0xffffffffff600000UL;
    memcpy(vsyscall_addr, &__dune_vsyscall_page, PAGE_SIZE);
}

void dune_syscall_handler(struct dune_tf *tf) {

}

void dune_trap_handler(int num, struct dune_tf *tf) {

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
void vmsa_config_init(struct vmsa_config *conf) {
    memset(conf, 0, sizeof(struct vmsa_config));
#ifndef __NO_ASM__
    __asm__ volatile (
        "leaq __dune_ret(%%rip), %0\n\t"   // 设置rip
        "xorq %1, %1\n\t"                  // 清空rsp
        "movq $0x2, %2"                   // 设置rflags
        : "=r" (conf->rip), "=r" (conf->rsp), "=r" (conf->rflags)
        : // 无输入操作数
        : // clobbered 寄存器
    );
#else
    conf->rip = (__u64) &__dune_ret;
    conf->rsp = 0;
    conf->rflags = 0x2;
#endif
}


/**
 * Initializes the VMPL library before the main program starts.
 * This function sets up VMPL2 access permission, builds assert, sets up signal, and sets up IDT.
 */
void vmpl_init_pre() {
    printf("vmpl_init_pre\n");
    // Grant VMPL2 access permission
    setup_vmpl();

    // Build assert
    vmpl_build_assert();

    // Setup signal
    setup_signal();

    // Setup IDT
    setup_idt();
}

/**
 * Initializes the VMPL library with the given configuration.
 *
 * @param conf The configuration to use for initialization.
 * @return 0 on success, or a negative error code on failure.
 */
int vmpl_init(struct vmsa_config *conf) {
    int rc;
    printf("vmpl_init\n");

    /* NOTE: We don't setup the general purpose registers because __dune_ret
     * will restore them as they were before the __dune_enter call */
    dune_fd = open("/dev/svsm-vmpl", O_RDWR);
    if (dune_fd == -1) {
        perror("Failed to open /dev/svsm-vmpl");
        rc = -errno;
        goto failed;
    }

    rc = __dune_enter(dune_fd, conf);
    if (rc) {
        printf("dune: entry to Dune mode failed, ret is %d\n", rc);
        perror("dune: entry to Dune mode failed");
        return -EIO;
    }

    return 0;
failed:
    return rc;
}

/**
 * Initializes the VMPL library after the main program has started.
 * This function sets up the necessary system calls for the library to function properly.
 *
 * @return 0 on success, -1 on failure.
 */
int vmpl_init_post() {

    // 1. 设置syscall
    setup_syscall();
    // 2. 设置vsyscall
    setup_vsyscall();

    return 0;
}

/**
 * Initializes a test for the VMPL library.
 * This function writes "Hello, World" to the standard output and exits.
 *
 * @return 0 on success.
 */
int vmpl_init_test() {
    const char *buf = "Hello, World\n";
    hp_write(STDOUT_FILENO, buf, strlen(buf));
    hp_exit();

    return 0;
}

/**
 * Initializes the VMPL library and enters the VMPL mode.
 * 
 * @return 0 if successful, otherwise an error code.
 */
int vmpl_enter() {
    int rc;
    struct vmsa_config *conf;

    printf("vmpl_enter\n");

    conf = malloc(sizeof(struct vmsa_config));
    vmsa_config_init(conf);

    vmpl_init_pre();

    rc = vmpl_init(conf);
    if (rc)
        goto failed;

    vmpl_init_post();
    vmpl_init_test();

    return 0;

failed:
    return rc;
}

/**
 * This function is used to exit the VMPL program.
 * It prints "vmpl_exit" to the console and returns 0.
 *
 * @return 0
 */
int vmpl_exit() {
    printf("vmpl_exit\n");

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
