#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <hotcalls/hotcalls.h>

#include "dunify.h"
#include "vmpl-hotcalls.h"

// Mark the branch as unlikely, since we expect to run in VMPL mode most of the time.
// This is a hint to the compiler to place this branch at the end of the function.
// This is done to reduce the size of the hot path.
#define unlikely(x) __builtin_expect(!!(x), 0)

ssize_t read(int fd, void *buf, size_t count)
{
	static typeof(&read) read_orig = NULL;
	if (unlikely(!read_orig))
		read_orig = dlsym(RTLD_NEXT, "read");

	if (unlikely(!hotcalls_initialized())) {
		return read_orig(fd, buf, count);
	}

	return hotcalls_read(fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	static typeof(&write) write_orig = NULL;
	if (unlikely(!write_orig))
		write_orig = dlsym(RTLD_NEXT, "write");

	if (unlikely(!hotcalls_initialized())) {
		return write_orig(fd, buf, count);
	}

	return hotcalls_write(fd, buf, count);
}

int close(int fd)
{
	static typeof(&close) close_orig = NULL;
	if (unlikely(!close_orig))
		close_orig = dlsym(RTLD_NEXT, "close");

	if (unlikely(!hotcalls_initialized())) {
		return close_orig(fd);
	}

	return hotcalls_close(fd);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	static typeof(&mmap) mmap_orig = NULL;
	if (unlikely(!mmap_orig))
		mmap_orig = dlsym(RTLD_NEXT, "mmap");

	if (unlikely(!hotcalls_initialized())) {
		return mmap_orig(addr, length, prot, flags, fd, offset);
	}

	return (void *)hotcalls_mmap(addr, length, prot, flags, fd, offset);
}

int mprotect(void *addr, size_t len, int prot)
{
	static typeof(&mprotect) mprotect_orig = NULL;
	if (unlikely(!mprotect_orig))
		mprotect_orig = dlsym(RTLD_NEXT, "mprotect");

	if (unlikely(!hotcalls_initialized())) {
		return mprotect_orig(addr, len, prot);
	}

	return hotcalls_mprotect(addr, len, prot);
}

int munmap(void *addr, size_t length)
{
	static typeof(&munmap) munmap_orig = NULL;
	if (unlikely(!munmap_orig))
		munmap_orig = dlsym(RTLD_NEXT, "munmap");

	if (unlikely(!hotcalls_initialized())) {
		return munmap_orig(addr, length);
	}

	return hotcalls_munmap(addr, length);
}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address)
{
	static typeof(&mremap) mremap_orig = NULL;
	if (unlikely(!mremap_orig))
		mremap_orig = dlsym(RTLD_NEXT, "mremap");

	if (unlikely(!hotcalls_initialized())) {
		return mremap_orig(old_address, old_size, new_size, flags, new_address);
	}

	return hotcalls_mremap(old_address, old_size, new_size, flags, new_address);
}

int ioctl(int fd, int request, ...)
{
	static typeof(&ioctl) ioctl_orig = NULL;
	if (unlikely(!ioctl_orig))
		ioctl_orig = dlsym(RTLD_NEXT, "ioctl");

	va_list ap;
	va_start(ap, request);
	void *argp = va_arg(ap, void *);
	va_end(ap);

	if (unlikely(!hotcalls_initialized())) {
		return ioctl_orig(fd, request, argp);
	}

	return hotcalls_ioctl(fd, request, argp);
}

long readv(int fd, const struct iovec *iov, int iovcnt)
{
	static typeof(&readv) readv_orig = NULL;
	if (unlikely(!readv_orig))
		readv_orig = dlsym(RTLD_NEXT, "readv");

	if (unlikely(!hotcalls_initialized())) {
		return readv_orig(fd, iov, iovcnt);
	}

	return hotcalls_readv(fd, iov, iovcnt);
}

long writev(int fd, const struct iovec *iov, int iovcnt)
{
	static typeof(&writev) writev_orig = NULL;
	if (unlikely(!writev_orig))
		writev_orig = dlsym(RTLD_NEXT, "writev");

	if (unlikely(!hotcalls_initialized())) {
		return writev_orig(fd, iov, iovcnt);
	}

	return hotcalls_writev(fd, iov, iovcnt);
}