#ifndef __HOTCALLS_H__
#define __HOTCALLS_H__

#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <hotcalls/hotcalls.h>

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

long hotcalls_read(int fd, void *buf, size_t count);
long hotcalls_write(int fd, const void *buf, size_t count);
long hotcalls_open(const char *pathname, int flags, mode_t mode);
long hotcalls_close(int fd);
long hotcalls_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
long hotcalls_mprotect(void *addr, size_t len, int prot);
long hotcalls_munmap(void *addr, size_t length);
long hotcalls_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);
long hotcalls_ioctl(int fd, unsigned long request, void *argp);
long hotcalls_readv(int fd, const struct iovec *iov, int iovcnt);
long hotcalls_writev(int fd, const struct iovec *iov, int iovcnt);

#endif // __HOTCALLS_H__