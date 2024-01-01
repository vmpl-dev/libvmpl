#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/fcntl.h>
#include <hotcalls/hotcalls.h>

#include "vmpl-hotcalls.h"

long hotcalls_read(int fd, void *buf, size_t count)
{
    hotcall_args_t args = {
        .sysnr = SYS_read,
        .rdi = fd,
        .rsi = (uint64_t)buf,
        .rdx = count,
    };
    return hotcalls_call(&args);
}

long hotcalls_write(int fd, const void *buf, size_t count)
{
    hotcall_args_t args = {
        .sysnr = SYS_write,
        .rdi = fd,
        .rsi = (uint64_t)buf,
        .rdx = count,
    };
    return hotcalls_call(&args);
}

long hotcalls_open(const char *pathname, int flags, mode_t mode)
{
    hotcall_args_t args = {
        .sysnr = SYS_open,
        .rdi = (uint64_t)pathname,
        .rsi = flags,
        .rdx = mode,
    };
    return hotcalls_call(&args);
}

long hotcalls_close(int fd)
{
    hotcall_args_t args = {
        .sysnr = SYS_close,
        .rdi = fd,
    };
    return hotcalls_call(&args);
}

long hotcalls_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    hotcall_args_t args = {
        .sysnr = SYS_mmap,
        .rdi = (uint64_t)addr,
        .rsi = length,
        .rdx = prot,
        .r10 = flags,
        .r8 = fd,
        .r9 = offset,
    };
    return hotcalls_call(&args);
}

long hotcalls_mprotect(void *addr, size_t len, int prot)
{
    hotcall_args_t args = {
        .sysnr = SYS_mprotect,
        .rdi = (uint64_t)addr,
        .rsi = len,
        .rdx = prot,
    };
    return hotcalls_call(&args);
}

long hotcalls_munmap(void *addr, size_t length)
{
    hotcall_args_t args = {
        .sysnr = SYS_munmap,
        .rdi = (uint64_t)addr,
        .rsi = length,
    };
    return hotcalls_call(&args);
}

long hotcalls_mremap(void *old_addr, size_t old_size, size_t new_size, int flags, void *new_addr)
{
    hotcall_args_t args = {
        .sysnr = SYS_mremap,
        .rdi = (uint64_t)old_addr,
        .rsi = old_size,
        .rdx = new_size,
        .r10 = flags,
        .r8 = (uint64_t)new_addr,
    };
    return hotcalls_call(&args);
}

long hotcalls_ioctl(int fd, unsigned long request, void *argp)
{
    hotcall_args_t args = {
        .sysnr = SYS_ioctl,
        .rdi = fd,
        .rsi = request,
        .rdx = (uint64_t)argp,
    };
    return hotcalls_call(&args);
}

long hotcalls_readv(int fd, const struct iovec *iov, int iovcnt)
{
    hotcall_args_t args = {
        .sysnr = SYS_readv,
        .rdi = fd,
        .rsi = (uint64_t)iov,
        .rdx = iovcnt,
    };
    return hotcalls_call(&args);
}

long hotcalls_writev(int fd, const struct iovec *iov, int iovcnt)
{
    hotcall_args_t args = {
        .sysnr = SYS_writev,
        .rdi = fd,
        .rsi = (uint64_t)iov,
        .rdx = iovcnt,
    };
    return hotcalls_call(&args);
}