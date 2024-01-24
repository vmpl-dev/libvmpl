#ifndef __VMPL_SYSCALL_
#define __VMPL_SYSCALL_

typedef long syscall_arg_t;
long vmpl_syscall(long sysnr, syscall_arg_t arg0, syscall_arg_t arg1,
                 syscall_arg_t arg2, syscall_arg_t arg3,
                 syscall_arg_t arg4, syscall_arg_t arg5);
void vmpl_syscall_test(void);

#endif
