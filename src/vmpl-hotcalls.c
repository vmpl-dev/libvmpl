#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <sys/fcntl.h>
#include <hotcalls/hotcalls.h>

#include "vmpl-hotcalls.h"

ssize_t hotcalls_read(int fd, void *buf, size_t count)
{
    hotcall_args_t args = {
        .sysnr = SYS_read,
        .rdi = fd,
        .rsi = (uint64_t)buf,
        .rdx = count,
    };
    return hotcalls_call(&args);
}

ssize_t hotcalls_write(int fd, const void *buf, size_t count)
{
    hotcall_args_t args = {
        .sysnr = SYS_write,
        .rdi = fd,
        .rsi = (uint64_t)buf,
        .rdx = count,
    };
    return hotcalls_call(&args);
}

int hotcalls_open(const char *pathname, int flags, mode_t mode)
{
    hotcall_args_t args = {
        .sysnr = SYS_open,
        .rdi = (uint64_t)pathname,
        .rsi = flags,
        .rdx = mode,
    };
    return hotcalls_call(&args);
}

int hotcalls_openat(int dirfd, const char *pathname, int flags, mode_t mode)
{
    hotcall_args_t args = {
        .sysnr = SYS_openat,
        .rdi = dirfd,
        .rsi = (uint64_t)pathname,
        .rdx = flags,
        .r10 = mode,
    };
    return hotcalls_call(&args);
}

int hotcalls_close(int fd)
{
    hotcall_args_t args = {
        .sysnr = SYS_close,
        .rdi = fd,
    };
    return hotcalls_call(&args);
}

int hotcalls_fcntl(int fd, int cmd, ... /* arg */ )
{
    hotcall_args_t args = {
        .sysnr = SYS_fcntl,
        .rdi = fd,
        .rsi = cmd,
    };
    va_list ap;
    va_start(ap, cmd);
    args.rdx = (uint64_t)va_arg(ap, void *);
    va_end(ap);
    return hotcalls_call(&args);
}

void *hotcalls_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
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
    return (void *)hotcalls_call(&args);
}

int hotcalls_mprotect(void *addr, size_t len, int prot)
{
    hotcall_args_t args = {
        .sysnr = SYS_mprotect,
        .rdi = (uint64_t)addr,
        .rsi = len,
        .rdx = prot,
    };
    return hotcalls_call(&args);
}

int hotcalls_munmap(void *addr, size_t length)
{
    hotcall_args_t args = {
        .sysnr = SYS_munmap,
        .rdi = (uint64_t)addr,
        .rsi = length,
    };
    return hotcalls_call(&args);
}

void *hotcalls_mremap(void *old_addr, size_t old_size, size_t new_size, int flags, void *new_addr)
{
    hotcall_args_t args = {
        .sysnr = SYS_mremap,
        .rdi = (uint64_t)old_addr,
        .rsi = old_size,
        .rdx = new_size,
        .r10 = flags,
        .r8 = (uint64_t)new_addr,
    };
    return (void *)hotcalls_call(&args);
}

int hotcalls_pkey_mprotect(void *addr, size_t len, int prot, int pkey)
{
    hotcall_args_t args = {
        .sysnr = SYS_pkey_mprotect,
        .rdi = (uint64_t)addr,
        .rsi = len,
        .rdx = prot,
        .r10 = pkey,
    };
    return hotcalls_call(&args);
}

int hotcalls_pkey_alloc(unsigned long flags, unsigned long init_val)
{
    hotcall_args_t args = {
        .sysnr = SYS_pkey_alloc,
        .rdi = flags,
        .rsi = init_val,
    };
    return hotcalls_call(&args);
}

int hotcalls_pkey_free(int pkey)
{
    hotcall_args_t args = {
        .sysnr = SYS_pkey_free,
        .rdi = pkey,
    };
    return hotcalls_call(&args);
}

int hotcalls_ioctl(int fd, unsigned long request, ...)
{
    hotcall_args_t args = {
        .sysnr = SYS_ioctl,
        .rdi = fd,
        .rsi = request,
    };
    va_list ap;
    va_start(ap, request);
    args.rdx = (uint64_t)va_arg(ap, void *);
    va_end(ap);
    return hotcalls_call(&args);
}

ssize_t hotcalls_readv(int fd, const struct iovec *iov, int iovcnt)
{
    hotcall_args_t args = {
        .sysnr = SYS_readv,
        .rdi = fd,
        .rsi = (uint64_t)iov,
        .rdx = iovcnt,
    };
    return hotcalls_call(&args);
}

ssize_t hotcalls_writev(int fd, const struct iovec *iov, int iovcnt)
{
    hotcall_args_t args = {
        .sysnr = SYS_writev,
        .rdi = fd,
        .rsi = (uint64_t)iov,
        .rdx = iovcnt,
    };
    return hotcalls_call(&args);
}

ssize_t hotcalls_preadv(int fd, void *buf, size_t count, off_t offset)
{
    hotcall_args_t args = {
        .sysnr = SYS_preadv,
        .rdi = fd,
        .rsi = (uint64_t)buf,
        .rdx = count,
        .r10 = offset,
    };
    return hotcalls_call(&args);
}

ssize_t hotcalls_pwritev(int fd, const void *buf, size_t count, off_t offset)
{
    hotcall_args_t args = {
        .sysnr = SYS_pwritev,
        .rdi = fd,
        .rsi = (uint64_t)buf,
        .rdx = count,
        .r10 = offset,
    };
    return hotcalls_call(&args);
}

ssize_t hotcalls_preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    hotcall_args_t args = {
        .sysnr = SYS_preadv2,
        .rdi = fd,
        .rsi = (uint64_t)iov,
        .rdx = iovcnt,
        .r10 = offset,
    };
    return hotcalls_call(&args);
}

ssize_t hotcalls_pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    hotcall_args_t args = {
        .sysnr = SYS_pwritev2,
        .rdi = fd,
        .rsi = (uint64_t)iov,
        .rdx = iovcnt,
        .r10 = offset,
    };
    return hotcalls_call(&args);
}

int hotcalls_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    hotcall_args_t args = {
        .sysnr = SYS_bind,
        .rdi = sockfd,
        .rsi = (uint64_t)addr,
        .rdx = addrlen,
    };
    return hotcalls_call(&args);
}

int hotcalls_listen(int sockfd, int backlog)
{
    hotcall_args_t args = {
        .sysnr = SYS_listen,
        .rdi = sockfd,
        .rsi = backlog,
    };
    return hotcalls_call(&args);
}

int hotcalls_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    hotcall_args_t args = {
        .sysnr = SYS_accept,
        .rdi = sockfd,
        .rsi = (uint64_t)addr,
        .rdx = (uint64_t)addrlen,
    };
    return hotcalls_call(&args);
}

int hotcalls_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    hotcall_args_t args = {
        .sysnr = SYS_connect,
        .rdi = sockfd,
        .rsi = (uint64_t)addr,
        .rdx = addrlen,
    };
    return hotcalls_call(&args);
}

int hotcalls_socket(int domain, int type, int protocol)
{
    hotcall_args_t args = {
        .sysnr = SYS_socket,
        .rdi = domain,
        .rsi = type,
        .rdx = protocol,
    };
    return hotcalls_call(&args);
}

int hotcalls_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
    hotcall_args_t args = {
        .sysnr = SYS_getsockopt,
        .rdi = sockfd,
        .rsi = level,
        .rdx = optname,
        .r10 = (uint64_t)optval,
        .r8 = (uint64_t)optlen,
    };
    return hotcalls_call(&args);
}

int hotcalls_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    hotcall_args_t args = {
        .sysnr = SYS_setsockopt,
        .rdi = sockfd,
        .rsi = level,
        .rdx = optname,
        .r10 = (uint64_t)optval,
        .r8 = optlen,
    };
    return hotcalls_call(&args);
}

int hotcalls_epoll_wait(int epfd, struct epoll_event *events,
                int maxevents, int timeout)
{
    hotcall_args_t args = {
        .sysnr = SYS_epoll_wait,
        .rdi = epfd,
        .rsi = (uint64_t)events,
        .rdx = maxevents,
        .r10 = timeout,
    };
    return hotcalls_call(&args);
}

int hotcalls_epoll_pwait(int epfd, struct epoll_event *events,
                int maxevents, int timeout,
                const sigset_t *sigmask)
{
    hotcall_args_t args = {
        .sysnr = SYS_epoll_pwait,
        .rdi = epfd,
        .rsi = (uint64_t)events,
        .rdx = maxevents,
        .r10 = timeout,
        .r8 = (uint64_t)sigmask,
    };
    return hotcalls_call(&args);
}