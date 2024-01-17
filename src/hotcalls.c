#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <hotcalls/hotcalls.h>

#include "config.h"
#include "dunify.h"
#include "vmpl-hotcalls.h"

#ifdef CONFIG_VMPL_HOTCALLS
static inline bool need_hotcalls(void)
{
	unsigned short cs;
	__asm__ __volatile__("movw %%cs, %0" : "=r"(cs));
	if ((cs & 0x3) == 0) {
		return hotcalls_initialized();
	} else {
		return false;
	}
}

/* Process */
ssize_t read(int fd, void *buf, size_t count)
{
	init_hook(read)
	if (unlikely(!need_hotcalls())) {
		return read_orig(fd, buf, count);
	}

	return hotcalls_read(fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	init_hook(write)
	if (unlikely(!need_hotcalls())) {
		return write_orig(fd, buf, count);
	}

	return hotcalls_write(fd, buf, count);
}

int open(const char *pathname, int flags, ...)
{
	va_list ap;
	va_start(ap, flags);
	mode_t mode = va_arg(ap, mode_t);
	va_end(ap);

	init_hook(open)
	if (unlikely(!need_hotcalls())) {
		return open_orig(pathname, flags, mode);
	}

	return hotcalls_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
	va_list ap;
	va_start(ap, flags);
	mode_t mode = va_arg(ap, mode_t);
	va_end(ap);

	init_hook(openat)
	if (unlikely(!need_hotcalls())) {
		return openat_orig(dirfd, pathname, flags, mode);
	}

	return hotcalls_openat(dirfd, pathname, flags, mode);
}

int close(int fd)
{
	init_hook(close)
	if (unlikely(!need_hotcalls())) {
		return close_orig(fd);
	}

	return hotcalls_close(fd);
}

int ioctl(int fd, int request, ...)
{
	va_list ap;
	va_start(ap, request);
	void *argp = va_arg(ap, void *);
	va_end(ap);

	init_hook(ioctl)
	if (unlikely(!need_hotcalls())) {
		return ioctl_orig(fd, request, argp);
	}

	return hotcalls_ioctl(fd, request, argp);
}

int fcntl(int fd, int cmd, ... /* arg */)
{
	va_list ap;
	va_start(ap, cmd);
	void *arg = va_arg(ap, void *);
	va_end(ap);

	init_hook(fcntl)
	if (unlikely(!need_hotcalls())) {
		return fcntl_orig(fd, cmd, arg);
	}

	return hotcalls_fcntl(fd, cmd, arg);
}

/* Memory */
int pkey_alloc(unsigned long flags, unsigned long init_val)
{
	init_hook(pkey_alloc)
	if (unlikely(!need_hotcalls())) {
		return pkey_alloc_orig(flags, init_val);
	}

	return hotcalls_pkey_alloc(flags, init_val);
}

int pkey_free(int pkey)
{
	init_hook(pkey_free)
	if (unlikely(!need_hotcalls())) {
		return pkey_free_orig(pkey);
	}

	return hotcalls_pkey_free(pkey);
}

/* File */
ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	init_hook(readv)
	if (unlikely(!need_hotcalls())) {
		return readv_orig(fd, iov, iovcnt);
	}

	return hotcalls_readv(fd, iov, iovcnt);

}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	init_hook(writev)
	if (unlikely(!need_hotcalls())) {
		return writev_orig(fd, iov, iovcnt);
	}

	return hotcalls_writev(fd, iov, iovcnt);
}

ssize_t preadv(int fd, const struct iovec *buf, int count, off_t offset)
{
	init_hook(preadv)
	if (unlikely(!need_hotcalls())) {
		return preadv_orig(fd, buf, count, offset);
	}

	return hotcalls_preadv(fd, buf, count, offset);
}

ssize_t pwritev(int fd, const struct iovec *buf, int count, off_t offset)
{
	init_hook(pwritev)
	if (unlikely(!need_hotcalls())) {
		return pwritev_orig(fd, buf, count, offset);
	}

	return hotcalls_pwritev(fd, buf, count, offset);
}

ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	init_hook(preadv2)
	if (unlikely(!need_hotcalls())) {
		return preadv2_orig(fd, iov, iovcnt, offset);
	}

	return hotcalls_preadv2(fd, iov, iovcnt, offset);
}

ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	init_hook(pwritev2)
	if (unlikely(!need_hotcalls())) {
		return pwritev2_orig(fd, iov, iovcnt, offset);
	}

	return hotcalls_pwritev2(fd, iov, iovcnt, offset);
}

/* Socket */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	init_hook(bind)
	if (unlikely(!need_hotcalls())) {
		return bind_orig(sockfd, addr, addrlen);
	}

	return hotcalls_bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog)
{
	init_hook(listen)
	if (unlikely(!need_hotcalls())) {
		return listen_orig(sockfd, backlog);
	}

	return hotcalls_listen(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	init_hook(accept)
	if (unlikely(!need_hotcalls())) {
		return accept_orig(sockfd, addr, addrlen);
	}

	return hotcalls_accept(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	init_hook(connect)
	if (unlikely(!need_hotcalls())) {
		return connect_orig(sockfd, addr, addrlen);
	}

	return hotcalls_connect(sockfd, addr, addrlen);
}

int socket(int domain, int type, int protocol)
{
	init_hook(socket)
	if (unlikely(!need_hotcalls())) {
		return socket_orig(domain, type, protocol);
	}

	return hotcalls_socket(domain, type, protocol);
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	init_hook(getsockopt)
	if (unlikely(!need_hotcalls())) {
		return getsockopt_orig(sockfd, level, optname, optval, optlen);
	}

	return hotcalls_getsockopt(sockfd, level, optname, optval, optlen);
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
	init_hook(setsockopt)
	if (unlikely(!need_hotcalls())) {
		return setsockopt_orig(sockfd, level, optname, optval, optlen);
	}

	return hotcalls_setsockopt(sockfd, level, optname, optval, optlen);
}

/* Epoll */
int epoll_wait(int epfd, struct epoll_event *events,
                int maxevents, int timeout)
{
	init_hook(epoll_wait)
	if (unlikely(!need_hotcalls())) {
		return epoll_wait_orig(epfd, events, maxevents, timeout);
	}

	return hotcalls_epoll_wait(epfd, events, maxevents, timeout);
}

int epoll_pwait(int epfd, struct epoll_event *events,
                int maxevents, int timeout,
                const sigset_t *sigmask)
{
	init_hook(epoll_pwait)
	if (unlikely(!need_hotcalls())) {
		return epoll_pwait_orig(epfd, events, maxevents, timeout, sigmask);
	}

	return hotcalls_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}
#endif