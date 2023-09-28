#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


#include "vc.h"
#include "hypercall.h"

#ifdef __HYPERPARAMS_
uint64_t hypercall(uint64_t syscall_number, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
	uint64_t val, resp;
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
#else
uint64_t hypercall(struct HypercallParam *param) {
    uint64_t ret;
    uint64_t val, resp;

    val = sev_es_rd_ghcb_msr();

    sev_es_wr_ghcb_msr(GHCB_MSR_VMPL_REQ_LEVEL(1));

    asm volatile(
        "movq %c[rax](%1), %%rax \n\t"
        "movq %c[rdi](%1), %%rdi \n\t"
        "movq %c[rsi](%1), %%rsi \n\t"
        "movq %c[rdx](%1), %%rdx \n\t"
        "movq %c[r10](%1), %%r10 \n\t"
        "movq %c[r8](%1), %%r8 \n\t"
        "movq %c[r9](%1), %%r9 \n\t"
        "rep; vmmcall\n\t"    // call the syscall
        "movq %%rax, %0\n\t" // move the return value to result
        : "=r"(ret)
        : "r"(param),
          [rax] "i"(offset_of(struct HypercallParam, rax)),
          [rdi] "i"(offset_of(struct HypercallParam, rdi)),
          [rsi] "i"(offset_of(struct HypercallParam, rsi)),
          [rdx] "i"(offset_of(struct HypercallParam, rdx)),
          [r10] "i"(offset_of(struct HypercallParam, r10)),
          [r8] "i"(offset_of(struct HypercallParam, r8)),
          [r9] "i"(offset_of(struct HypercallParam, r9))
        : "rax", "rdx", "rdi", "rsi", "r8", "r9", "r10");

    resp = sev_es_rd_ghcb_msr();

    sev_es_wr_ghcb_msr(val);

    if (GHCB_MSR_INFO(resp) != GHCB_MSR_VMPL_RES)
        ret = -EINVAL;

    if (GHCB_MSR_VMPL_RESP_VAL(resp) != 0)
        ret = -EINVAL;

    return ret;
}

int hp_read(int fildes, uint64_t phy_addr, uint64_t nbyte) {
    struct HypercallParam param = {
        .rax = __NR_read,
        .rdi = fildes,
        .rsi = phy_addr,
        .rdx = nbyte,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_write(int fildes, uint64_t phy_addr, uint64_t nbyte) {
    struct HypercallParam param = {
        .rax = __NR_write,
        .rdi = fildes,
        .rsi = phy_addr,
        .rdx = nbyte,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_open(uint64_t paddr) {
    struct HypercallParam param = {
        .rax = __NR_open,
        .rdi = paddr,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_close(int fildes) {
    struct HypercallParam param = {
        .rax = __NR_close,
        .rdi = fildes,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_stat(const char *pathname, struct stat *statbuf) {
    struct HypercallParam param = {
        .rax = __NR_stat,
        .rdi = (uint64_t) pathname,
        .rsi = (uint64_t) statbuf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fstat(int fd, struct stat *statbuf) {
    struct HypercallParam param = {
        .rax = __NR_fstat,
        .rdi = (uint64_t) fd,
        .rsi = (uint64_t) statbuf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_lstat(const char *pathname, struct stat *statbuf) {
    struct HypercallParam param = {
        .rax = __NR_lstat,
        .rdi = (uint64_t) pathname,
        .rsi = (uint64_t) statbuf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    struct HypercallParam param = {
        .rax = __NR_poll,
        .rdi = (uint64_t) fds,
        .rsi = nfds,
        .rdx = timeout,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_lseek(int fildes, uint32_t offset, int whence) {
    struct HypercallParam param = {
        .rax = __NR_lseek,
        .rdi = fildes,
        .rsi = offset,
        .rdx = whence,
    };
    int ret = hypercall(&param);
    return ret;
}

void *hp_mmap(void *addr, size_t length, int prot, int flags,
              int fd, off_t offset) {
    struct HypercallParam param = {
        .rax = __NR_mmap,
        .rdi = (uint64_t) addr,
        .rsi = length,
        .rdx = prot,
        .r10 = flags,
        .r8 = fd,
        .r9 = offset
    };
    void *ret_addr = hypercall(&param);
    return ret_addr;
}

int hp_mprotect(void *addr, size_t len, int prot) {
    struct HypercallParam param = {
        .rax = __NR_mprotect,
        .rdi = (uint64_t) addr,
        .rsi = len,
        .rdx = prot,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_munmap(void *addr, size_t length) {
    struct HypercallParam param = {
        .rax = __NR_munmap,
        .rdi = (uint64_t) addr,
        .rsi = length,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_brk(void *addr) {
    struct HypercallParam param = {
        .rax = __NR_brk,
        .rdi = (uint64_t) addr,
    };
    int ret = hypercall(&param);
    return ret;
}

pid_t hp_getpid(void) {
    struct HypercallParam param = {
        .rax = __NR_getpid,
    };
    pid_t pid = hypercall(&param);
    return pid;
}

pid_t hp_gettid(void) {
    struct HypercallParam param = {
        .rax = __NR_gettid,
    };
    pid_t tid = hypercall(&param);
    return tid;
}

void hp_exit(void) {
    struct HypercallParam param = {
        .rax = __NR_exit,
    };
    hypercall(&param);
}


#endif