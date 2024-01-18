#ifndef __VMPL_HOTCALLS_H__
#define __VMPL_HOTCALLS_H__

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>

#include <hotcalls/hotcalls.h>

#define __alias(name) __attribute__((alias(#name)))
typedef unsigned long syscall_arg_t;

static inline long hotcalls0(syscall_arg_t sysnr)
{
    hotcall_args_t args = {
        .sysnr = sysnr,
    };
    return hotcalls_call(&args);
}
static inline long hotcalls1(syscall_arg_t sysnr, syscall_arg_t arg1)
{
    hotcall_args_t args = {
        .sysnr = sysnr,
        .rdi = arg1,
    };
    return hotcalls_call(&args);
}
static inline long hotcalls2(syscall_arg_t sysnr, syscall_arg_t arg1, syscall_arg_t arg2)
{
    hotcall_args_t args = {
        .sysnr = sysnr,
        .rdi = arg1,
        .rsi = arg2,
    };
    return hotcalls_call(&args);
}
static inline long hotcalls3(syscall_arg_t sysnr, syscall_arg_t arg1, syscall_arg_t arg2, syscall_arg_t arg3)
{
    hotcall_args_t args = {
        .sysnr = sysnr,
        .rdi = arg1,
        .rsi = arg2,
        .rdx = arg3,
    };
    return hotcalls_call(&args);
}
static inline long hotcalls4(syscall_arg_t sysnr, syscall_arg_t arg1, syscall_arg_t arg2,
                             syscall_arg_t arg3, syscall_arg_t arg4)
{
    hotcall_args_t args = {
        .sysnr = sysnr,
        .rdi = arg1,
        .rsi = arg2,
        .rdx = arg3,
        .r10 = arg4,
    };
    return hotcalls_call(&args);
}
static inline long hotcalls5(syscall_arg_t sysnr, syscall_arg_t arg1, syscall_arg_t arg2,
                             syscall_arg_t arg3, syscall_arg_t arg4, syscall_arg_t arg5)
{
    hotcall_args_t args = {
        .sysnr = sysnr,
        .rdi = arg1,
        .rsi = arg2,
        .rdx = arg3,
        .r10 = arg4,
        .r8 = arg5,
    };
    return hotcalls_call(&args);
}
static inline long hotcalls6(syscall_arg_t sysnr, syscall_arg_t arg1, syscall_arg_t arg2, syscall_arg_t arg3, 
                             syscall_arg_t arg4, syscall_arg_t arg5, syscall_arg_t arg6)
{
    hotcall_args_t args = {
        .sysnr = sysnr,
        .rdi = arg1,
        .rsi = arg2,
        .rdx = arg3,
        .r10 = arg4,
        .r8 = arg5,
        .r9 = arg6,
    };
    return hotcalls_call(&args);
}

/* Memory */
#define hotcalls_mmap(addr, length, prot, flags, fd, offset) \
    hotcalls6(SYS_mmap, addr, length, prot, flags, fd, offset)

#define hotcalls_mprotect(addr, len, prot) \
    hotcalls3(SYS_mprotect, addr, len, prot)

#define hotcalls_munmap(addr, length) \
    hotcalls2(SYS_munmap, addr, length)

#define hotcalls_mremap(old_address, old_size, new_size, flags, new_address) \
    hotcalls5(SYS_mremap, old_address, old_size, new_size, flags, new_address)

#define hotcalls_pkey_mprotect(addr, len, prot, pkey) \
    hotcalls4(SYS_pkey_mprotect, addr, len, prot, pkey)

#endif // __VMPL_HOTCALLS_H__