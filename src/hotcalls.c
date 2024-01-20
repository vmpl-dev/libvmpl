#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/sysinfo.h>
#include <sys/epoll.h>
#include <sys/resource.h>
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

	return hotcalls3(SYS_read, fd, buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
	init_hook(write)
	if (unlikely(!need_hotcalls())) {
		return write_orig(fd, buf, count);
	}

	return hotcalls3(SYS_write, fd, buf, count);
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

	return hotcalls3(SYS_open, pathname, flags, mode);
}

int close(int fd)
{
	init_hook(close)
	if (unlikely(!need_hotcalls())) {
		return close_orig(fd);
	}

	return hotcalls1(SYS_close, fd);
}

// stat
int stat(const char *pathname, struct stat *statbuf)
{
    init_hook(stat)
    if (unlikely(!need_hotcalls())) {
        return stat_orig(pathname, statbuf);
    }

    return hotcalls2(SYS_stat, pathname, statbuf);
}

// fstat
int fstat(int fd, struct stat *statbuf)
{
    init_hook(fstat)
    if (unlikely(!need_hotcalls())) {
        return fstat_orig(fd, statbuf);
    }

    return hotcalls2(SYS_fstat, fd, statbuf);
}

// lstat
int lstat(const char *pathname, struct stat *statbuf)
{
    init_hook(lstat)
    if (unlikely(!need_hotcalls())) {
        return lstat_orig(pathname, statbuf);
    }

    return hotcalls2(SYS_lstat, pathname, statbuf);
}

// poll
int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    init_hook(poll);
    if (unlikely(!need_hotcalls())) {
        return poll_orig(fds, nfds, timeout);
    }

    return hotcalls3(SYS_poll, fds, nfds, timeout);
}

// lseek
int lseek(int fd, off_t offset, int whence)
{
    init_hook(lseek);
    if (unlikely(!need_hotcalls())) {
        return lseek_orig(fd, offset, whence);
    }

    return hotcalls3(SYS_lseek, fd, offset, whence);
}

#ifndef CONFIG_VMPL_MM
// Wrapper for mmap
void *mmap(void *addr, size_t length, int prot, int flags,
           int fd, off_t offset)
{
    init_hook(mmap);
    if (unlikely(!need_hotcalls())) {
        return mmap_orig(addr, length, prot, flags, fd, offset);
    }

    return (void *)hotcalls6(SYS_mmap, addr, length, prot, flags, fd, offset);
}

// Wrapper for mprotect
int mprotect(void *addr, size_t len, int prot)
{
    init_hook(mprotect);
    if (unlikely(!need_hotcalls())) {
        return mprotect_orig(addr, len, prot);
    }

    return hotcalls3(SYS_mprotect, addr, len, prot);
}

// Wrapper for munmap
int munmap(void *addr, size_t length)
{
    init_hook(munmap);
    if (unlikely(!need_hotcalls())) {
        return munmap_orig(addr, length);
    }

    return hotcalls2(SYS_munmap, addr, length);
}

// Wrapper for mremap
void *mremap(void *old_address, size_t old_size,
             size_t new_size, int flags, ... /* void *new_address */)
{
    void *new_address = NULL;
	if (flags | MREMAP_FIXED) {
		va_list ap;
		va_start(ap, flags);
		new_address = va_arg(ap, void *);
		va_end(ap);
	}

    init_hook(mremap);
    if (unlikely(!need_hotcalls())) {
        return mremap_orig(old_address, old_size, new_size, flags, new_address);
    }

    return (void *)hotcalls5(SYS_mremap, old_address, old_size, new_size, flags, new_address);
}

// Wrapper for pkey_mprotect
int pkey_mprotect(void *addr, size_t len, int prot, int pkey)
{
    init_hook(pkey_mprotect);
    if (unlikely(!need_hotcalls())) {
        errno = -ENOSYS;
        return -1;
    }

    return hotcalls4(SYS_pkey_mprotect, addr, len, prot, pkey);
}
#endif

int brk(void *addr)
{
	init_hook(brk);
	if (unlikely(!need_hotcalls())) {
		return brk_orig(addr);
	}

	return hotcalls1(SYS_brk, addr);
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

	return hotcalls3(SYS_ioctl, fd, request, argp);
}

// pread64
ssize_t pread64(int fd, void *buf, size_t count, off_t offset)
{
    init_hook(pread64)
    if (unlikely(!need_hotcalls())) {
        return pread64_orig(fd, buf, count, offset);
    }

    return hotcalls4(SYS_pread64, fd, buf, count, offset);
}

// pwrite64
ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset)
{
    init_hook(pwrite64)
    if (unlikely(!need_hotcalls())) {
        return pwrite64_orig(fd, buf, count, offset);
    }

    return hotcalls4(SYS_pwrite64, fd, buf, count, offset);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	init_hook(readv)
	if (unlikely(!need_hotcalls())) {
		return readv_orig(fd, iov, iovcnt);
	}

	return hotcalls3(SYS_readv, fd, iov, iovcnt);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	init_hook(writev)
	if (unlikely(!need_hotcalls())) {
		return writev_orig(fd, iov, iovcnt);
	}

	return hotcalls3(SYS_writev, fd, iov, iovcnt);
}

int access(const char *pathname, int mode)
{
    init_hook(access);
    if (unlikely(!need_hotcalls())) {
        return access_orig(pathname, mode);
    }

    return hotcalls2(SYS_access, pathname, mode);
}

int pipe(int pipefd[2])
{
    init_hook(pipe);
    if (unlikely(!need_hotcalls())) {
        return pipe_orig(pipefd);
    }

    return hotcalls1(SYS_pipe, pipefd);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    init_hook(select);
    if (unlikely(!need_hotcalls())) {
        return select_orig(nfds, readfds, writefds, exceptfds, timeout);
    }

    return hotcalls5(SYS_select, nfds, readfds, writefds, exceptfds, timeout);
}

int msync(void *addr, size_t length, int flags)
{
    init_hook(msync);
    if (unlikely(!need_hotcalls())) {
        return msync_orig(addr, length, flags);
    }

    return hotcalls3(SYS_msync, addr, length, flags);
}

int mincore(void *addr, size_t length, unsigned char *vec)
{
    init_hook(mincore);
    if (unlikely(!need_hotcalls())) {
        return mincore_orig(addr, length, vec);
    }

    return hotcalls3(SYS_mincore, addr, length, vec);
}

int madvise(void *addr, size_t length, int advice)
{
    init_hook(madvise);
    if (unlikely(!need_hotcalls())) {
        return madvise_orig(addr, length, advice);
    }

    return hotcalls3(SYS_madvise, addr, length, advice);
}

// shmget
int shmget(key_t key, size_t size, int shmflg)
{
    init_hook(shmget)
    if (unlikely(!need_hotcalls())) {
        return shmget_orig(key, size, shmflg);
    }

    return hotcalls3(SYS_shmget, key, size, shmflg);
}

// shmat
void *shmat(int shmid, const void *shmaddr, int shmflg)
{
    init_hook(shmat)
    if (unlikely(!need_hotcalls())) {
        return shmat_orig(shmid, shmaddr, shmflg);
    }

    return hotcalls3(SYS_shmat, shmid, shmaddr, shmflg);
}

int shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
    init_hook(shmctl)
    if (unlikely(!need_hotcalls())) {
        return shmctl_orig(shmid, cmd, buf);
    }

    return hotcalls3(SYS_shmctl, shmid, cmd, buf);
}

int dup(int oldfd)
{
    init_hook(dup)
    if (unlikely(!need_hotcalls())) {
        return dup_orig(oldfd);
    }

    return hotcalls1(SYS_dup, oldfd);
}

int dup2(int oldfd, int newfd)
{
    init_hook(dup2)
    if (unlikely(!need_hotcalls())) {
        return dup2_orig(oldfd, newfd);
    }

    return hotcalls2(SYS_dup2, oldfd, newfd);
}

int getitimer(int which, struct itimerval *value)
{
    init_hook(getitimer);
    if (unlikely(!need_hotcalls())) {
        return getitimer_orig(which, value);
    }

    return hotcalls2(SYS_getitimer, which, value);
}

unsigned int alarm(unsigned int seconds)
{
    init_hook(alarm);
    if (unlikely(!need_hotcalls())) {
        return alarm_orig(seconds);
    }

    return hotcalls1(SYS_alarm, seconds);
}

int setitimer(int which, const struct itimerval *value, struct itimerval *old_value)
{
    init_hook(setitimer);
    if (unlikely(!need_hotcalls())) {
        return setitimer_orig(which, value, old_value);
    }

    return hotcalls3(SYS_setitimer, which, value, old_value);
}

// Hotcalls wrapper for getpid
pid_t getpid(void)
{
    init_hook(getpid)
    if (unlikely(!need_hotcalls())) {
        return getpid_orig();
    }

    return hotcalls0(SYS_getpid);
}

// Hotcalls wrapper for sendfile
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    init_hook(sendfile)
    if (unlikely(!need_hotcalls())) {
        return sendfile_orig(out_fd, in_fd, offset, count);
    }

    return hotcalls4(SYS_sendfile, out_fd, in_fd, offset, count);
}

// Hotcalls wrapper for socket
int socket(int domain, int type, int protocol)
{
    init_hook(socket)
    if (unlikely(!need_hotcalls())) {
        return socket_orig(domain, type, protocol);
    }

    return hotcalls3(SYS_socket, domain, type, protocol);
}

// Hotcalls wrapper for connect
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    init_hook(connect)
    if (unlikely(!need_hotcalls())) {
        return connect_orig(sockfd, addr, addrlen);
    }

    return hotcalls3(SYS_connect, sockfd, addr, addrlen);
}

// Hotcalls wrapper for accept
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    init_hook(accept)
    if (unlikely(!need_hotcalls())) {
        return accept_orig(sockfd, addr, addrlen);
    }

    return hotcalls3(SYS_accept, sockfd, addr, addrlen);
}

// Hotcalls wrapper for sendto
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    init_hook(sendto)
    if (unlikely(!need_hotcalls())) {
        return sendto_orig(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    return hotcalls6(SYS_sendto, sockfd, buf, len, flags, dest_addr, addrlen);
}

// Hotcalls wrapper for recvfrom
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    init_hook(recvfrom)
    if (unlikely(!need_hotcalls())) {
        return recvfrom_orig(sockfd, buf, len, flags, src_addr, addrlen);
    }

    return hotcalls6(SYS_recvfrom, sockfd, buf, len, flags, src_addr, addrlen);
}

// Hotcalls wrapper for sendmsg
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    init_hook(sendmsg)
    if (unlikely(!need_hotcalls())) {
        return sendmsg_orig(sockfd, msg, flags);
    }

    return hotcalls3(SYS_sendmsg, sockfd, msg, flags);
}

// Hotcalls wrapper for recvmsg
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    init_hook(recvmsg)
    if (unlikely(!need_hotcalls())) {
        return recvmsg_orig(sockfd, msg, flags);
    }

    return hotcalls3(SYS_recvmsg, sockfd, msg, flags);
}

// Hotcalls wrapper for shutdown
int shutdown(int sockfd, int how)
{
    init_hook(shutdown)
    if (unlikely(!need_hotcalls())) {
        return shutdown_orig(sockfd, how);
    }

    return hotcalls2(SYS_shutdown, sockfd, how);
}

// Hotcalls wrapper for bind
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    init_hook(bind)
    if (unlikely(!need_hotcalls())) {
        return bind_orig(sockfd, addr, addrlen);
    }

    return hotcalls3(SYS_bind, sockfd, addr, addrlen);
}

// Hotcalls wrapper for listen
int listen(int sockfd, int backlog)
{
    init_hook(listen)
    if (unlikely(!need_hotcalls())) {
        return listen_orig(sockfd, backlog);
    }

    return hotcalls2(SYS_listen, sockfd, backlog);
}

// Hotcalls wrapper for getsockname
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    init_hook(getsockname)
    if (unlikely(!need_hotcalls())) {
        return getsockname_orig(sockfd, addr, addrlen);
    }

    return hotcalls3(SYS_getsockname, sockfd, addr, addrlen);
}

// Hotcalls wrapper for getpeername
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    init_hook(getpeername)
    if (unlikely(!need_hotcalls())) {
        return getpeername_orig(sockfd, addr, addrlen);
    }

    return hotcalls3(SYS_getpeername, sockfd, addr, addrlen);
}

// Hotcalls wrapper for socketpair
int socketpair(int domain, int type, int protocol, int sv[2])
{
    init_hook(socketpair)
    if (unlikely(!need_hotcalls())) {
        return socketpair_orig(domain, type, protocol, sv);
    }

    return hotcalls4(SYS_socketpair, domain, type, protocol, sv);
}

// Hotcalls wrapper for setsockopt
int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    init_hook(setsockopt)
    if (unlikely(!need_hotcalls())) {
        return setsockopt_orig(sockfd, level, optname, optval, optlen);
    }

    return hotcalls5(SYS_setsockopt, sockfd, level, optname, optval, optlen);
}

// Hotcalls wrapper for getsockopt
int getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t *optlen)
{
    init_hook(getsockopt)
    if (unlikely(!need_hotcalls())) {
        return getsockopt_orig(sockfd, level, optname, optval, optlen);
    }

    return hotcalls5(SYS_getsockopt, sockfd, level, optname, optval, optlen);
}

int uname(struct utsname *buf)
{
    init_hook(uname)
    if (unlikely(!need_hotcalls())) {
        return uname_orig(buf);
    }

    return hotcalls1(SYS_uname, buf);
}

// shmdt
int shmdt(const void *shmaddr)
{
    init_hook(shmdt)
    if (unlikely(!need_hotcalls())) {
        return shmdt_orig(shmaddr);
    }

    return hotcalls1(SYS_shmdt, shmaddr);
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

	return hotcalls3(SYS_fcntl, fd, cmd, arg);
}


int flock(int fd, int operation)
{
    init_hook(flock)
    if (unlikely(!need_hotcalls())) {
        return flock_orig(fd, operation);
    }

    return hotcalls2(SYS_flock, fd, operation);
}

int fsync(int fd)
{
    init_hook(fsync)
    if (unlikely(!need_hotcalls())) {
        return fsync_orig(fd);
    }

    return hotcalls1(SYS_fsync, fd);
}

int fdatasync(int fd)
{
    init_hook(fdatasync)
    if (unlikely(!need_hotcalls())) {
        return fdatasync_orig(fd);
    }

    return hotcalls1(SYS_fdatasync, fd);
}

int truncate(const char *path, off_t length)
{
    init_hook(truncate)
    if (unlikely(!need_hotcalls())) {
        return truncate_orig(path, length);
    }

    return hotcalls2(SYS_truncate, path, length);
}

int ftruncate(int fd, off_t length)
{
    init_hook(ftruncate)
    if (unlikely(!need_hotcalls())) {
        return ftruncate_orig(fd, length);
    }

    return hotcalls2(SYS_ftruncate, fd, length);
}

// Hotcalls wrapper for getdents
ssize_t getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
    init_hook(getdents)
    if (unlikely(!need_hotcalls())) {
        return getdents_orig(fd, dirp, count);
    }

    return hotcalls3(SYS_getdents, fd, dirp, count);
}

// Hotcalls wrapper for getcwd
char *getcwd(char *buf, size_t size)
{
    init_hook(getcwd)
    if (unlikely(!need_hotcalls())) {
        return getcwd_orig(buf, size);
    }

    return hotcalls2(SYS_getcwd, buf, size);
}

// Hotcalls wrapper for chdir
int chdir(const char *path)
{
    init_hook(chdir)
    if (unlikely(!need_hotcalls())) {
        return chdir_orig(path);
    }

    return hotcalls1(SYS_chdir, path);
}

// Hotcalls wrapper for fchdir
int fchdir(int fd)
{
    init_hook(fchdir)
    if (unlikely(!need_hotcalls())) {
        return fchdir_orig(fd);
    }

    return hotcalls1(SYS_fchdir, fd);
}

// Hotcalls wrapper for rename
int rename(const char *oldpath, const char *newpath)
{
    init_hook(rename)
    if (unlikely(!need_hotcalls())) {
        return rename_orig(oldpath, newpath);
    }

    return hotcalls2(SYS_rename, oldpath, newpath);
}

// Hotcalls wrapper for mkdir
int mkdir(const char *pathname, mode_t mode)
{
    init_hook(mkdir)
    if (unlikely(!need_hotcalls())) {
        return mkdir_orig(pathname, mode);
    }

    return hotcalls2(SYS_mkdir, pathname, mode);
}

// Hotcalls wrapper for rmdir
int rmdir(const char *pathname)
{
    init_hook(rmdir)
    if (unlikely(!need_hotcalls())) {
        return rmdir_orig(pathname);
    }

    return hotcalls1(SYS_rmdir, pathname);
}

// Hotcalls wrapper for creat
int creat(const char *pathname, mode_t mode)
{
    init_hook(creat)
    if (unlikely(!need_hotcalls())) {
        return creat_orig(pathname, mode);
    }

    return hotcalls2(SYS_creat, pathname, mode);
}

// Hotcalls wrapper for link
int link(const char *oldpath, const char *newpath)
{
    init_hook(link)
    if (unlikely(!need_hotcalls())) {
        return link_orig(oldpath, newpath);
    }

    return hotcalls2(SYS_link, oldpath, newpath);
}

// Hotcalls wrapper for unlink
int unlink(const char *pathname)
{
    init_hook(unlink)
    if (unlikely(!need_hotcalls())) {
        return unlink_orig(pathname);
    }

    return hotcalls1(SYS_unlink, pathname);
}

// Hotcalls wrapper for symlink
int symlink(const char *target, const char *linkpath)
{
    init_hook(symlink)
    if (unlikely(!need_hotcalls())) {
        return symlink_orig(target, linkpath);
    }

    return hotcalls2(SYS_symlink, target, linkpath);
}

// Hotcalls wrapper for readlink
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    init_hook(readlink)
    if (unlikely(!need_hotcalls())) {
        return readlink_orig(pathname, buf, bufsiz);
    }

    return hotcalls3(SYS_readlink, pathname, buf, bufsiz);
}

// Hotcalls wrapper for chmod
int chmod(const char *pathname, mode_t mode)
{
    init_hook(chmod)
    if (unlikely(!need_hotcalls())) {
        return chmod_orig(pathname, mode);
    }

    return hotcalls2(SYS_chmod, pathname, mode);
}

// Hotcalls wrapper for fchmod
int fchmod(int fd, mode_t mode)
{
    init_hook(fchmod)
    if (unlikely(!need_hotcalls())) {
        return fchmod_orig(fd, mode);
    }

    return hotcalls2(SYS_fchmod, fd, mode);
}

// Hotcalls wrapper for chown
int chown(const char *pathname, uid_t owner, gid_t group)
{
    init_hook(chown)
    if (unlikely(!need_hotcalls())) {
        return chown_orig(pathname, owner, group);
    }

    return hotcalls3(SYS_chown, pathname, owner, group);
}

// Hotcalls wrapper for fchown
int fchown(int fd, uid_t owner, gid_t group)
{
    init_hook(fchown)
    if (unlikely(!need_hotcalls())) {
        return fchown_orig(fd, owner, group);
    }

    return hotcalls3(SYS_fchown, fd, owner, group);
}

// Hotcalls wrapper for lchown
int lchown(const char *pathname, uid_t owner, gid_t group)
{
    init_hook(lchown)
    if (unlikely(!need_hotcalls())) {
        return lchown_orig(pathname, owner, group);
    }

    return hotcalls3(SYS_lchown, pathname, owner, group);
}

// Hotcalls wrapper for umask
mode_t umask(mode_t mask)
{
    init_hook(umask)
    if (unlikely(!need_hotcalls())) {
        return umask_orig(mask);
    }

    return hotcalls1(SYS_umask, mask);
}

// Hotcalls wrapper for getrlimit
int getrlimit(int resource, struct rlimit *rlim)
{
    init_hook(getrlimit)
    if (unlikely(!need_hotcalls())) {
        return getrlimit_orig(resource, rlim);
    }

    return hotcalls2(SYS_getrlimit, resource, rlim);
}

// Hotcalls wrapper for getrusage
int getrusage(int who, struct rusage *r_usage)
{
    init_hook(getrusage)
    if (unlikely(!need_hotcalls())) {
        return getrusage_orig(who, r_usage);
    }

    return hotcalls2(SYS_getrusage, who, r_usage);
}

// Hotcalls wrapper for sysinfo
int sysinfo(struct sysinfo *info)
{
    init_hook(sysinfo)
    if (unlikely(!need_hotcalls())) {
        return sysinfo_orig(info);
    }

    return hotcalls1(SYS_sysinfo, info);
}

// Hotcalls wrapper for times
clock_t times(struct tms *buf)
{
    init_hook(times)
    if (unlikely(!need_hotcalls())) {
        return times_orig(buf);
    }

    return hotcalls1(SYS_times, buf);
}

long ptrace(int request, pid_t pid, void *addr, void *data)
{
    init_hook(ptrace);
    if (unlikely(!need_hotcalls())) {
        return ptrace_orig(request, pid, addr, data);
    }

    return hotcalls4(SYS_ptrace, request, pid, addr, data);
}

int syslog(int type, const char *bufp, int len)
{
    init_hook(syslog);
    if (unlikely(!need_hotcalls())) {
        return syslog_orig(type, bufp, len);
    }

    return hotcalls3(SYS_syslog, type, bufp, len);
}

int utime(const char *filename, const struct utimbuf *times)
{
    init_hook(utime);
    if (unlikely(!need_hotcalls())) {
        return utime_orig(filename, times);
    }

    return hotcalls2(SYS_utime, filename, times);
}

int mknod(const char *pathname, mode_t mode, dev_t dev)
{
    init_hook(mknod);
    if (unlikely(!need_hotcalls())) {
        return mknod_orig(pathname, mode, dev);
    }

    return hotcalls3(SYS_mknod, pathname, mode, dev);
}

int uselib(const char *library)
{
    init_hook(uselib);
    if (unlikely(!need_hotcalls())) {
        return uselib_orig(library);
    }

    return hotcalls1(SYS_uselib, library);
}

int personality(unsigned long persona)
{
    init_hook(personality);
    if (unlikely(!need_hotcalls())) {
        return personality_orig(persona);
    }

    return hotcalls1(SYS_personality, persona);
}

// Hotcalls wrapper for ustat
int ustat(dev_t dev, struct ustat *ubuf)
{
    init_hook(ustat)
    if (unlikely(!need_hotcalls())) {
        return ustat_orig(dev, ubuf);
    }

    return hotcalls2(SYS_ustat, dev, ubuf);
}

// Hotcalls wrapper for statfs
int statfs(const char *path, struct statfs *buf)
{
    init_hook(statfs)
    if (unlikely(!need_hotcalls())) {
        return statfs_orig(path, buf);
    }

    return hotcalls2(SYS_statfs, path, buf);
}

// Hotcalls wrapper for fstatfs
int fstatfs(int fd, struct statfs *buf)
{
    init_hook(fstatfs)
    if (unlikely(!need_hotcalls())) {
        return fstatfs_orig(fd, buf);
    }

    return hotcalls2(SYS_fstatfs, fd, buf);
}

// Hotcalls wrapper for sysfs
int sysfs(int option, unsigned long arg1, unsigned long arg2)
{
    init_hook(sysfs)
    if (unlikely(!need_hotcalls())) {
        return sysfs_orig(option, arg1, arg2);
    }

    return hotcalls3(SYS_sysfs, option, arg1, arg2);
}

// Hotcalls wrapper for mlock
int mlock(const void *addr, size_t len)
{
    init_hook(mlock)
    if (unlikely(!need_hotcalls())) {
        return mlock_orig(addr, len);
    }

    return hotcalls2(SYS_mlock, addr, len);
}

// Hotcalls wrapper for munlock
int munlock(const void *addr, size_t len)
{
    init_hook(munlock)
    if (unlikely(!need_hotcalls())) {
        return munlock_orig(addr, len);
    }

    return hotcalls2(SYS_munlock, addr, len);
}

// Hotcalls wrapper for mlockall
int mlockall(int flags)
{
    init_hook(mlockall)
    if (unlikely(!need_hotcalls())) {
        return mlockall_orig(flags);
    }

    return hotcalls1(SYS_mlockall, flags);
}

// Hotcalls wrapper for munlockall
int munlockall(void)
{
    init_hook(munlockall)
    if (unlikely(!need_hotcalls())) {
        return munlockall_orig();
    }

    return hotcalls0(SYS_munlockall);
}

// Hotcalls wrapper for sync
void sync(void)
{
    init_hook(sync)
    if (unlikely(!need_hotcalls())) {
        sync_orig();
        return;
    }

    hotcalls0(SYS_sync);
}


// Hotcalls wrapper for mount
int mount(const char *source, const char *target,
          const char *filesystemtype, unsigned long mountflags,
          const void *data)
{
    init_hook(mount)
    if (unlikely(!need_hotcalls())) {
        return mount_orig(source, target, filesystemtype, mountflags, data);
    }

    return hotcalls5(SYS_mount, source, target, filesystemtype, mountflags, data);
}

// Hotcalls wrapper for umount2
int umount2(const char *target, int flags)
{
    init_hook(umount2)
    if (unlikely(!need_hotcalls())) {
        return umount2_orig(target, flags);
    }

    return hotcalls2(SYS_umount2, target, flags);
}

// Hotcalls wrapper for readahead
ssize_t readahead(int fd, off64_t offset, size_t count)
{
    init_hook(readahead)
    if (unlikely(!need_hotcalls())) {
        return readahead_orig(fd, offset, count);
    }

    return hotcalls3(SYS_readahead, fd, offset, count);
}

// getxattr
ssize_t getxattr(const char *path, const char *name, void *value, size_t size)
{
    init_hook(getxattr)
    if (unlikely(!need_hotcalls())) {
        return getxattr_orig(path, name, value, size);
    }

    return hotcalls4(SYS_getxattr, path, name, value, size);
}

// lgetxattr
ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size)
{
    init_hook(lgetxattr)
    if (unlikely(!need_hotcalls())) {
        return lgetxattr_orig(path, name, value, size);
    }

    return hotcalls4(SYS_lgetxattr, path, name, value, size);
}

// Hotcalls wrapper for getdents64
ssize_t getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
    init_hook(getdents64)
    if (unlikely(!need_hotcalls())) {
        return getdents64_orig(fd, dirp, count);
    }

    return hotcalls3(SYS_getdents64, fd, dirp, count);
}


/* Epoll */
int epoll_wait(int epfd, struct epoll_event *events,
                int maxevents, int timeout)
{
	init_hook(epoll_wait)
	if (unlikely(!need_hotcalls())) {
		return epoll_wait_orig(epfd, events, maxevents, timeout);
	}

	return hotcalls4(SYS_epoll_wait, epfd, events, maxevents, timeout);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	init_hook(epoll_ctl);
	if (unlikely(!need_hotcalls())) {
		return epoll_ctl_orig(epfd, op, fd, event);
	}

	return hotcalls4(SYS_epoll_ctl, epfd, op, fd, event);
}


// Hotcalls wrapper for openat
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

	return hotcalls3(SYS_openat, pathname, flags, mode);
}

// Hotcalls wrapper for mkdirat
int mkdirat(int dirfd, const char *pathname, mode_t mode)
{
    init_hook(mkdirat)
    if (unlikely(!need_hotcalls())) {
        return mkdirat_orig(dirfd, pathname, mode);
    }

    return hotcalls3(SYS_mkdirat, dirfd, pathname, mode);
}

// Hotcalls wrapper for mknodat
int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)
{
    init_hook(mknodat)
    if (unlikely(!need_hotcalls())) {
        return mknodat_orig(dirfd, pathname, mode, dev);
    }

    return hotcalls4(SYS_mknodat, dirfd, pathname, mode, dev);
}

// Hotcalls wrapper for fchownat
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
{
    init_hook(fchownat)
    if (unlikely(!need_hotcalls())) {
        return fchownat_orig(dirfd, pathname, owner, group, flags);
    }

    return hotcalls5(SYS_fchownat, dirfd, pathname, owner, group, flags);
}

// Hotcalls wrapper for futimesat
int futimesat(int dirfd, const char *pathname, const struct timeval times[2])
{
    init_hook(futimesat)
    if (unlikely(!need_hotcalls())) {
        return futimesat_orig(dirfd, pathname, times);
    }

    return hotcalls3(SYS_futimesat, dirfd, pathname, times);
}

// Hotcalls wrapper for newfstatat
int newfstatat(int dirfd, const char *pathname, struct stat *buf, int flags)
{
    init_hook(newfstatat)
    if (unlikely(!need_hotcalls())) {
        return newfstatat_orig(dirfd, pathname, buf, flags);
    }

    return hotcalls4(SYS_newfstatat, dirfd, pathname, buf, flags);
}

// Hotcalls wrapper for unlinkat
int unlinkat(int dirfd, const char *pathname, int flags)
{
    init_hook(unlinkat)
    if (unlikely(!need_hotcalls())) {
        return unlinkat_orig(dirfd, pathname, flags);
    }

    return hotcalls3(SYS_unlinkat, dirfd, pathname, flags);
}

// Hotcalls wrapper for renameat
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    init_hook(renameat)
    if (unlikely(!need_hotcalls())) {
        return renameat_orig(olddirfd, oldpath, newdirfd, newpath);
    }

    return hotcalls4(SYS_renameat, olddirfd, oldpath, newdirfd, newpath);
}

// Hotcalls wrapper for linkat
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
    init_hook(linkat)
    if (unlikely(!need_hotcalls())) {
        return linkat_orig(olddirfd, oldpath, newdirfd, newpath, flags);
    }

    return hotcalls5(SYS_linkat, olddirfd, oldpath, newdirfd, newpath, flags);
}

// Hotcalls wrapper for symlinkat
int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    init_hook(symlinkat)
    if (unlikely(!need_hotcalls())) {
        return symlinkat_orig(target, newdirfd, linkpath);
    }

    return hotcalls3(SYS_symlinkat, target, newdirfd, linkpath);
}

// Hotcalls wrapper for readlinkat
ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    init_hook(readlinkat)
    if (unlikely(!need_hotcalls())) {
        return readlinkat_orig(dirfd, pathname, buf, bufsiz);
    }

    return hotcalls4(SYS_readlinkat, dirfd, pathname, buf, bufsiz);
}

// Hotcalls wrapper for fchmodat
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
    init_hook(fchmodat)
    if (unlikely(!need_hotcalls())) {
        return fchmodat_orig(dirfd, pathname, mode, flags);
    }

    return hotcalls4(SYS_fchmodat, dirfd, pathname, mode, flags);
}

// Hotcalls wrapper for faccessat
int faccessat(int dirfd, const char *pathname, int mode, int flags)
{
    init_hook(faccessat)
    if (unlikely(!need_hotcalls())) {
        return faccessat_orig(dirfd, pathname, mode, flags);
    }

    return hotcalls4(SYS_faccessat, dirfd, pathname, mode, flags);
}

// Hotcalls wrapper for splice
ssize_t splice(int fd_in, loff_t *off_in, int fd_out,
               loff_t *off_out, size_t len, unsigned int flags)
{
    init_hook(splice)
    if (unlikely(!need_hotcalls())) {
        return splice_orig(fd_in, off_in, fd_out, off_out, len, flags);
    }

    return hotcalls6(SYS_splice, fd_in, off_in, fd_out, off_out, len, flags);
}

// Hotcalls wrapper for tee
ssize_t tee(int fdin, int fdout, size_t len, unsigned int flags)
{
    init_hook(tee)
    if (unlikely(!need_hotcalls())) {
        return tee_orig(fdin, fdout, len, flags);
    }

    return hotcalls4(SYS_tee, fdin, fdout, len, flags);
}

// Hotcalls wrapper for sync_file_range
int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)
{
    init_hook(sync_file_range)
    if (unlikely(!need_hotcalls())) {
        return sync_file_range_orig(fd, offset, nbytes, flags);
    }

    return hotcalls4(SYS_sync_file_range, fd, offset, nbytes, flags);
}

// Hotcalls wrapper for vmsplice
ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags)
{
    init_hook(vmsplice)
    if (unlikely(!need_hotcalls())) {
        return vmsplice_orig(fd, iov, nr_segs, flags);
    }

    return hotcalls4(SYS_vmsplice, fd, iov, nr_segs, flags);
}

// Hotcalls wrapper for move_pages
long move_pages(int pid, unsigned long nr_pages, const void **pages,
                const int *nodes, int *status, int flags)
{
    init_hook(move_pages)
    if (unlikely(!need_hotcalls())) {
        return move_pages_orig(pid, nr_pages, pages, nodes, status, flags);
    }

    return hotcalls6(SYS_move_pages, pid, nr_pages, pages, nodes, status, flags);
}

// Hotcalls wrapper for utimensat
int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags)
{
    init_hook(utimensat)
    if (unlikely(!need_hotcalls())) {
        return utimensat_orig(dirfd, pathname, times, flags);
    }

    return hotcalls4(SYS_utimensat, dirfd, pathname, times, flags);
}

int epoll_pwait(int epfd, struct epoll_event *events,
                int maxevents, int timeout,
                const sigset_t *sigmask)
{
	init_hook(epoll_pwait)
	if (unlikely(!need_hotcalls())) {
		return epoll_pwait_orig(epfd, events, maxevents, timeout, sigmask);
	}

	return hotcalls5(SYS_epoll_pwait, epfd, events, maxevents, timeout, sigmask);
}

// Hotcalls wrapper for accept4
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    init_hook(accept4)
    if (unlikely(!need_hotcalls())) {
        return accept4_orig(sockfd, addr, addrlen, flags);
    }

    return hotcalls4(SYS_accept4, sockfd, addr, addrlen, flags);
}

// Hotcalls wrapper for epoll_create1
int epoll_create1(int flags)
{
    init_hook(epoll_create1)
    if (unlikely(!need_hotcalls())) {
        return epoll_create1_orig(flags);
    }

    return hotcalls1(SYS_epoll_create1, flags);
}

// Hotcalls wrapper for dup3
int dup3(int oldfd, int newfd, int flags)
{
    init_hook(dup3)
    if (unlikely(!need_hotcalls())) {
        return dup3_orig(oldfd, newfd, flags);
    }

    return hotcalls3(SYS_dup3, oldfd, newfd, flags);
}

// Hotcalls wrapper for pipe2
int pipe2(int pipefd[2], int flags)
{
    init_hook(pipe2)
    if (unlikely(!need_hotcalls())) {
        return pipe2_orig(pipefd, flags);
    }

    return hotcalls2(SYS_pipe2, pipefd, flags);
}

/* File */
ssize_t preadv(int fd, const struct iovec *buf, int count, off_t offset)
{
	init_hook(preadv)
	if (unlikely(!need_hotcalls())) {
		return preadv_orig(fd, buf, count, offset);
	}

	return hotcalls4(SYS_preadv, fd, buf, count, offset);
}

ssize_t pwritev(int fd, const struct iovec *buf, int count, off_t offset)
{
	init_hook(pwritev)
	if (unlikely(!need_hotcalls())) {
		return pwritev_orig(fd, buf, count, offset);
	}

	return hotcalls4(SYS_pwritev, fd, buf, count, offset);
}

// Hotcalls wrapper for recvmmsg
int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                      unsigned int flags, struct timespec *timeout)
{
    init_hook(recvmmsg)
    if (unlikely(!need_hotcalls())) {
        return recvmmsg_orig(sockfd, msgvec, vlen, flags, timeout);
    }

    return hotcalls5(SYS_recvmmsg, sockfd, msgvec, vlen, flags, timeout);
}

// prlimit64
int prlimit64(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit)
{
    init_hook(prlimit64)
    if (unlikely(!need_hotcalls())) {
        return prlimit64_orig(pid, resource, new_limit, old_limit);
    }

    return hotcalls4(SYS_prlimit64, pid, resource, new_limit, old_limit);
}

// Hotcalls wrapper for syncfs
int syncfs(int fd)
{
    init_hook(syncfs)
    if (unlikely(!need_hotcalls())) {
        return syncfs_orig(fd);
    }

    return hotcalls1(SYS_syncfs, fd);
}

// Hotcalls wrapper for sendmmsg
int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags)
{
    init_hook(sendmmsg)
    if (unlikely(!need_hotcalls())) {
        return sendmmsg_orig(sockfd, msgvec, vlen, flags);
    }

    return hotcalls4(SYS_sendmmsg, sockfd, msgvec, vlen, flags);
}

ssize_t process_vm_readv(pid_t pid,
                          const struct iovec *lvec, unsigned long liovcnt,
                          const struct iovec *rvec, unsigned long riovcnt,
                          unsigned long flags)
{
    init_hook(process_vm_readv);
    if (unlikely(!need_hotcalls())) {
        return process_vm_readv_orig(pid, lvec, liovcnt, rvec, riovcnt, flags);
    }

    return hotcalls6(SYS_process_vm_readv, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

ssize_t process_vm_writev(pid_t pid,
                           const struct iovec *lvec, unsigned long liovcnt,
                           const struct iovec *rvec, unsigned long riovcnt,
                           unsigned long flags)
{
    init_hook(process_vm_writev);
    if (unlikely(!need_hotcalls())) {
        return process_vm_writev_orig(pid, lvec, liovcnt, rvec, riovcnt, flags);
    }

    return hotcalls6(SYS_process_vm_writev, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

// Hotcalls wrapper for renameat2
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)
{
    init_hook(renameat2)
    if (unlikely(!need_hotcalls())) {
        return renameat2_orig(olddirfd, oldpath, newdirfd, newpath, flags);
    }

    return hotcalls5(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
}

// Hotcalls wrapper for seccomp
int seccomp(unsigned int op, unsigned int flags, const void *uargs)
{
    init_hook(seccomp)
    if (unlikely(!need_hotcalls())) {
        return seccomp_orig(op, flags, uargs);
    }

    return hotcalls3(SYS_seccomp, op, flags, uargs);
}

// Hotcalls wrapper for getrandom
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
    init_hook(getrandom)
    if (unlikely(!need_hotcalls())) {
        return getrandom_orig(buf, buflen, flags);
    }

    return hotcalls3(SYS_getrandom, buf, buflen, flags);
}

int memfd_create(const char *name, unsigned int flags)
{
    init_hook(memfd_create);
    if (unlikely(!need_hotcalls())) {
        return memfd_create_orig(name, flags);
    }

    return hotcalls2(SYS_memfd_create, name, flags);
}

int mlock2(const void *addr, size_t length, int flags)
{
    init_hook(mlock2);
    if (unlikely(!need_hotcalls())) {
        return mlock2_orig(addr, length, flags);
    }

    return hotcalls3(SYS_mlock2, addr, length, flags);
}

ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                        loff_t *off_out, size_t len, unsigned int flags)
{
    init_hook(copy_file_range);
    if (unlikely(!need_hotcalls())) {
        return copy_file_range_orig(fd_in, off_in, fd_out, off_out, len, flags);
    }

    return hotcalls6(SYS_copy_file_range, fd_in, off_in, fd_out, off_out, len, flags);
}

ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	init_hook(preadv2)
	if (unlikely(!need_hotcalls())) {
		return preadv2_orig(fd, iov, iovcnt, offset);
	}

	return hotcalls4(SYS_preadv2, fd, iov, iovcnt, offset);
}

ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	init_hook(pwritev2)
	if (unlikely(!need_hotcalls())) {
		return pwritev2_orig(fd, iov, iovcnt, offset);
	}

	return hotcalls4(SYS_pwritev2, fd, iov, iovcnt, offset);
}

// Hotcalls wrapper for pkey_alloc
int pkey_alloc(unsigned long flags, unsigned long init_val)
{
    init_hook(pkey_alloc)
    if (unlikely(!need_hotcalls())) {
        return pkey_alloc_orig(flags, init_val);
    }

    return hotcalls2(SYS_pkey_alloc, flags, init_val);
}

// Hotcalls wrapper for pkey_free
int pkey_free(int pkey)
{
    init_hook(pkey_free)
    if (unlikely(!need_hotcalls())) {
        return pkey_free_orig(pkey);
    }

    return hotcalls1(SYS_pkey_free, pkey);
}

// Hotcalls wrapper for statx
int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *buffer)
{
    init_hook(statx)
    if (unlikely(!need_hotcalls())) {
        return statx_orig(dirfd, pathname, flags, mask, buffer);
    }

    return hotcalls5(SYS_statx, dirfd, pathname, flags, mask, buffer);
}

// Hotcalls wrapper for openat2
int openat2(int dirfd, const char *pathname, struct open_how *how, size_t size)
{
    init_hook(openat2)
    if (unlikely(!need_hotcalls())) {
        return openat2_orig(dirfd, pathname, how, size);
    }

    return hotcalls4(SYS_openat2, dirfd, pathname, how, size);
}

// Hotcalls wrapper for faccessat2
int faccessat2(int dirfd, const char *pathname, int mode, int flags)
{
    init_hook(faccessat2)
    if (unlikely(!need_hotcalls())) {
        return faccessat2_orig(dirfd, pathname, mode, flags);
    }

    return hotcalls4(SYS_faccessat2, dirfd, pathname, mode, flags);
}

#endif