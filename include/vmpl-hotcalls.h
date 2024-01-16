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

/* Process */
ssize_t hotcalls_read(int fd, void *buf, size_t count);
ssize_t hotcalls_write(int fd, const void *buf, size_t count);
int hotcalls_open(const char *pathname, int flags, mode_t mode);
int hotcalls_openat(int dirfd, const char *pathname, int flags, mode_t mode);
int hotcalls_close(int fd);
int hotcalls_fcntl(int fd, int cmd, ... /* arg */);

/* Memory */
void *hotcalls_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int hotcalls_mprotect(void *addr, size_t len, int prot);
int hotcalls_munmap(void *addr, size_t length);
void *hotcalls_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address);
int hotcalls_pkey_mprotect(void *addr, size_t len, int prot, int pkey);
int hotcalls_pkey_alloc(unsigned long flags, unsigned long init_val);
int hotcalls_pkey_free(int pkey);

/* File */
int hotcalls_ioctl(int fd, unsigned long request, ...);
ssize_t hotcalls_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t hotcalls_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t hotcalls_preadv(int fd, void *buf, size_t count, off_t offset);
ssize_t hotcalls_pwritev(int fd, const void *buf, size_t count, off_t offset);
ssize_t hotcalls_preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t hotcalls_pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset);

/* Socket */
int hotcalls_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int hotcalls_listen(int sockfd, int backlog);
int hotcalls_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int hotcalls_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int hotcalls_socket(int domain, int type, int protocol);
int hotcalls_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int hotcalls_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

/* Epoll */
int hotcalls_epoll_wait(int epfd, struct epoll_event *events,
                int maxevents, int timeout);
int hotcalls_epoll_pwait(int epfd, struct epoll_event *events,
                int maxevents, int timeout,
                const sigset_t *sigmask);
#endif // __VMPL_HOTCALLS_H__