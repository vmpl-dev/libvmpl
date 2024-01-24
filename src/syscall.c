#include "syscall.h"
#include "log.h"

#include <sys/syscall.h>

long vmpl_syscall(long sysnr, syscall_arg_t arg0, syscall_arg_t arg1,
				 syscall_arg_t arg2, syscall_arg_t arg3,
				 syscall_arg_t arg4, syscall_arg_t arg5)
{
	long ret;
	__asm__ volatile("movq %1, %%rax\n\t"
					 "movq %2, %%rdi\n\t"
					 "movq %3, %%rsi\n\t"
					 "movq %4, %%rdx\n\t"
					 "movq %5, %%r10\n\t"
					 "movq %6, %%r8\n\t"
					 "movq %7, %%r9\n\t"
					 "syscall\n\t"
					 "mov %%rax, %0\n\t"
					 : "=r"(ret)
					 : "r"(sysnr), "r"(arg0), "r"(arg1), "r"(arg2), "r"(arg3),
					   "r"(arg4), "r"(arg5)
					 : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory");

	log_debug("vmpl_syscall: sysnr = %d, ret = %d", sysnr, ret);
	return ret;
}

void vmpl_syscall_test(void)
{
	long ret;
	// Test syscall from the G0
	log_info("Test syscall from the G0");
	ret = vmpl_syscall(SYS_getpid, 0, 0, 0, 0, 0, 0);
	log_success("Test syscall from the G0 passed, ret = %d", ret);
}