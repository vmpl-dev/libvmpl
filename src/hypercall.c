#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "vc.h"
#include "hypercall.h"

#define RUN_VMPL Vmpl0
#ifdef __HYPERPARAMS_
static inline uint64_t vmmcall6(uint64_t syscall_number, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    // Assuming that syscall_number, arg1, arg2, arg3, arg4, arg5, and arg6 are variables
    uint64_t result;
    asm volatile(
        "movq %1, %%rax\n" // move the syscall number to RAX register
        "movq %2, %%rdi\n" // move the first argument to RDI register
        "movq %3, %%rsi\n" // move the second argument to RSI register
        "movq %4, %%rdx\n" // move the third argument to RDX register
        "movq %5, %%r10\n" // move the fourth argument to R10 register
        "movq %6, %%r8\n"  // move the fifth argument to R8 register
        "movq %7, %%r9\n"  // move the sixth argument to R9 register
        "rep; vmmcall\n"   // call the syscall
        "movq %%rax, %0\n" // move the return value to result
        : "=r"(result)
        : "r"(syscall_number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6)
        : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9");

    return result;
}

uint64_t hypercall_msr(uint64_t syscall_number, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)
{
    uint64_t val, resp;
    int ret;

    val = sev_es_rd_ghcb_msr();

    sev_es_wr_ghcb_msr(GHCB_MSR_VMPL_REQ_LEVEL(RUN_VMPL));

    vmmcall6(syscall_number, arg1, arg2, arg3, arg4, arg5, arg6);

    resp = sev_es_rd_ghcb_msr();

    sev_es_wr_ghcb_msr(val);

    if (GHCB_MSR_INFO(resp) != GHCB_MSR_VMPL_RES)
        ret = -EINVAL;

    if (GHCB_MSR_VMPL_RESP_VAL(resp) != 0)
        ret = -EINVAL;

    return ret;
}
#else
static inline uint64_t vmmcall(struct HypercallParam *param)
{
    uint64_t ret;
    asm volatile(
        "movq %c[rax](%1), %%rax \n\t"
        "movq %c[rdi](%1), %%rdi \n\t"
        "movq %c[rsi](%1), %%rsi \n\t"
        "movq %c[rdx](%1), %%rdx \n\t"
        "movq %c[r10](%1), %%r10 \n\t"
        "movq %c[r8](%1), %%r8 \n\t"
        "movq %c[r9](%1), %%r9 \n\t"
        "rep; vmmcall\n\t"   // call the syscall
        "movq %%rax, %0\n\t" // move the return value to result
        : "=r"(ret)
        : "r"(param),
          [rax] "i"(offset_of(struct HypercallParam, rax)),
          [rdi] "i"(offset_of(struct HypercallParam, rdi)),
          [rsi] "i"(offset_of(struct HypercallParam, rsi)),
          [rdx] "i"(offset_of(struct HypercallParam, rdx)),
          [r10] "i"(offset_of(struct HypercallParam, r10)),
          [r8] "i"(offset_of(struct HypercallParam, r8)),
          [r9] "i"(offset_of(struct HypercallParam, r9))
        : "rax", "rdx", "rdi", "rsi", "r8", "r9", "r10");

    return ret;
}

static uint64_t hypercall_msr(struct HypercallParam *param)
{
    uint64_t ret;
    uint64_t val, resp;

    val = sev_es_rd_ghcb_msr();

    sev_es_wr_ghcb_msr(GHCB_MSR_VMPL_REQ_LEVEL(RUN_VMPL));

    ret = vmmcall(param);

    resp = sev_es_rd_ghcb_msr();

    sev_es_wr_ghcb_msr(val);

    if (GHCB_MSR_INFO(resp) != GHCB_MSR_VMPL_RES)
        ret = -EINVAL;

    if (GHCB_MSR_VMPL_RESP_VAL(resp) != 0)
        ret = -EINVAL;

    return ret;
}

static uint64_t hypercall_ghcb(struct HypercallParam *param)
{
	uint64_t ret;
	u64 val, resp;

	Ghcb *ghcb = vc_get_ghcb();

	ghcb_set_version(ghcb, GHCB_PROTOCOL_MIN);
    ghcb_set_usage(ghcb, GHCB_DEFAULT_USAGE);

	ghcb_set_sw_exit_code(ghcb, GHCB_NAE_RUN_VMPL);
	ghcb_set_sw_exit_info_1(ghcb, RUN_VMPL);
	ghcb_set_sw_exit_info_2(ghcb, 0);

    ret = vmmcall(param);

    if (!ghcb_is_sw_exit_info_1_valid(ghcb)) {
        ret = -EINVAL;
    }

    if (LOWER_32BITS(ghcb_get_sw_exit_info_1(ghcb)) != 0) {
        ret = -EINVAL;
    }

    return ret;
}

uint64_t hypercall(struct HypercallParam *param) {
    return hypercall_msr(param);
}
#endif

ssize_t hp_read(int fd, void *buf, size_t count)
{
    struct HypercallParam param = {
        .rax = __NR_read,
        .rdi = fd,
        .rsi = (uint64_t)buf,
        .rdx = count,
    };
    int ret = hypercall(&param);
    return ret;
}

ssize_t hp_write(int fd, const void *buf, size_t count)
{
    struct HypercallParam param = {
        .rax = __NR_write,
        .rdi = fd,
        .rsi = (uint64_t)buf,
        .rdx = count,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

int hp_open(const char *pathname, int flags, mode_t mode)
{
    struct HypercallParam param = {
        .rax = __NR_open,
        .rdi = (uint64_t)pathname,
        .rsi = flags,
        .rdx = mode,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_close(int fd)
{
    struct HypercallParam param = {
        .rax = __NR_close,
        .rdi = fd,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_stat(const char *pathname, struct stat *statbuf)
{
    struct HypercallParam param = {
        .rax = __NR_stat,
        .rdi = (uint64_t)pathname,
        .rsi = (uint64_t)statbuf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fstat(int fd, struct stat *statbuf)
{
    struct HypercallParam param = {
        .rax = __NR_fstat,
        .rdi = (uint64_t)fd,
        .rsi = (uint64_t)statbuf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_lstat(const char *pathname, struct stat *statbuf)
{
    struct HypercallParam param = {
        .rax = __NR_lstat,
        .rdi = (uint64_t)pathname,
        .rsi = (uint64_t)statbuf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    struct HypercallParam param = {
        .rax = __NR_poll,
        .rdi = (uint64_t)fds,
        .rsi = nfds,
        .rdx = timeout,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_lseek(int fildes, uint32_t offset, int whence)
{
    struct HypercallParam param = {
        .rax = __NR_lseek,
        .rdi = fildes,
        .rsi = offset,
        .rdx = whence,
    };
    int ret = hypercall(&param);
    return ret;
}

void *hp_mmap(void *addr, size_t length, int prot, int flags,
              int fd, off_t offset)
{
    struct HypercallParam param = {
        .rax = __NR_mmap,
        .rdi = (uint64_t)addr,
        .rsi = length,
        .rdx = prot,
        .r10 = flags,
        .r8 = fd,
        .r9 = offset};
    void *ret_addr = (void *)hypercall(&param);
    return ret_addr;
}

int hp_mprotect(void *addr, size_t len, int prot)
{
    struct HypercallParam param = {
        .rax = __NR_mprotect,
        .rdi = (uint64_t)addr,
        .rsi = len,
        .rdx = prot,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_munmap(void *addr, size_t length)
{
    struct HypercallParam param = {
        .rax = __NR_munmap,
        .rdi = (uint64_t)addr,
        .rsi = length,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_brk(void *addr)
{
    struct HypercallParam param = {
        .rax = __NR_brk,
        .rdi = (uint64_t)addr,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_pipe(int pipefd[2])
{
    struct HypercallParam param = {
        .rax = __NR_pipe,
        .rdi = (uint64_t)pipefd,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout)
{
    struct HypercallParam param = {
        .rax = __NR_select,
        .rdi = nfds,
        .rsi = (uint64_t)readfds,
        .rdx = (uint64_t)writefds,
        .r10 = (uint64_t)exceptfds,
        .r8 = (uint64_t)timeout,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_sched_yield(void)
{
    struct HypercallParam param = {
        .rax = __NR_sched_yield,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_shmget(key_t key, size_t size, int shmflg)
{
    struct HypercallParam param = {
        .rax = __NR_shmget,
        .rdi = key,
        .rsi = size,
        .rdx = shmflg,
    };
    int ret = hypercall(&param);
    return ret;
}

void *hp_shmat(int shmid, const void *shmaddr, int shmflg)
{
    struct HypercallParam param = {
        .rax = __NR_shmat,
        .rdi = shmid,
        .rsi = (uint64_t)shmaddr,
        .rdx = shmflg,
    };
    void *ret_addr = (void *)hypercall(&param);
    return ret_addr;
}

int hp_shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
    struct HypercallParam param = {
        .rax = __NR_shmctl,
        .rdi = shmid,
        .rsi = cmd,
        .rdx = (uint64_t)buf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_dup(int oldfd)
{
    struct HypercallParam param = {
        .rax = __NR_dup,
        .rdi = oldfd,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_dup2(int oldfd, int newfd)
{
    struct HypercallParam param = {
        .rax = __NR_dup2,
        .rdi = oldfd,
        .rsi = newfd,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_pause(void)
{
    struct HypercallParam param = {
        .rax = __NR_pause,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_nanosleep(const struct timespec *req, struct timespec *rem)
{
    struct HypercallParam param = {
        .rax = __NR_nanosleep,
        .rdi = (uint64_t)req,
        .rsi = (uint64_t)rem,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_getitimer(int which, struct itimerval *curr_value)
{
    struct HypercallParam param = {
        .rax = __NR_getitimer,
        .rdi = which,
        .rsi = (uint64_t)curr_value,
    };
    int ret = hypercall(&param);
    return ret;
}

unsigned int hp_alarm(unsigned int seconds)
{
    struct HypercallParam param = {
        .rax = __NR_alarm,
        .rdi = seconds,
    };
    unsigned int ret = hypercall(&param);
    return ret;
}

int hp_setitimer(int which, const struct itimerval *new_value,
                 struct itimerval *old_value)
{
    struct HypercallParam param = {
        .rax = __NR_setitimer,
        .rdi = which,
        .rsi = (uint64_t)new_value,
        .rdx = (uint64_t)old_value,
    };
    int ret = hypercall(&param);
    return ret;
}

pid_t hp_getpid(void)
{
    struct HypercallParam param = {
        .rax = __NR_getpid,
    };
    pid_t pid = hypercall(&param);
    return pid;
}

ssize_t hp_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    struct HypercallParam param = {
        .rax = __NR_sendfile,
        .rdi = out_fd,
        .rsi = in_fd,
        .rdx = (uint64_t)offset,
        .r10 = count,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

int hp_socket(int domain, int type, int protocol)
{
    struct HypercallParam param = {
        .rax = __NR_socket,
        .rdi = domain,
        .rsi = type,
        .rdx = protocol,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_connect(int sockfd, const struct sockaddr *addr,
               socklen_t addrlen)
{
    struct HypercallParam param = {
        .rax = __NR_connect,
        .rdi = sockfd,
        .rsi = (uint64_t)addr,
        .rdx = addrlen,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct HypercallParam param = {
        .rax = __NR_accept,
        .rdi = sockfd,
        .rsi = (uint64_t)addr,
        .rdx = (uint64_t)addrlen,
    };
    int ret = hypercall(&param);
    return ret;
}

ssize_t hp_sendto(int sockfd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen)
{
    struct HypercallParam param = {
        .rax = __NR_sendto,
        .rdi = sockfd,
        .rsi = (uint64_t)buf,
        .rdx = len,
        .r10 = flags,
        .r8 = (uint64_t)dest_addr,
        .r9 = addrlen,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

ssize_t hp_recvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen)
{
    struct HypercallParam param = {
        .rax = __NR_recvfrom,
        .rdi = sockfd,
        .rsi = (uint64_t)buf,
        .rdx = len,
        .r10 = flags,
        .r8 = (uint64_t)src_addr,
        .r9 = (uint64_t)addrlen,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

ssize_t hp_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_sendmsg,
        .rdi = sockfd,
        .rsi = (uint64_t)msg,
        .rdx = flags,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

ssize_t hp_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_recvmsg,
        .rdi = sockfd,
        .rsi = (uint64_t)msg,
        .rdx = flags,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

int hp_bind(int sockfd, const struct sockaddr *addr,
            socklen_t addrlen)
{
    struct HypercallParam param = {
        .rax = __NR_bind,
        .rdi = sockfd,
        .rsi = (uint64_t)addr,
        .rdx = addrlen,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_listen(int sockfd, int backlog)
{
    struct HypercallParam param = {
        .rax = __NR_listen,
        .rdi = sockfd,
        .rsi = backlog,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct HypercallParam param = {
        .rax = __NR_getsockname,
        .rdi = sockfd,
        .rsi = (uint64_t)addr,
        .rdx = (uint64_t)addrlen,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct HypercallParam param = {
        .rax = __NR_getpeername,
        .rdi = sockfd,
        .rsi = (uint64_t)addr,
        .rdx = (uint64_t)addrlen,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_socketpair(int domain, int type, int protocol, int sv[2])
{
    struct HypercallParam param = {
        .rax = __NR_socketpair,
        .rdi = domain,
        .rsi = type,
        .rdx = protocol,
        .r10 = (uint64_t)sv,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_getsockopt(int sockfd, int level, int optname,
                  void *optval, socklen_t *optlen)
{
    struct HypercallParam param = {
        .rax = __NR_getsockopt,
        .rdi = sockfd,
        .rsi = level,
        .rdx = optname,
        .r10 = (uint64_t)optval,
        .r8 = (uint64_t)optlen,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setsockopt(int sockfd, int level, int optname,
                  const void *optval, socklen_t optlen)
{
    struct HypercallParam param = {
        .rax = __NR_setsockopt,
        .rdi = sockfd,
        .rsi = level,
        .rdx = optname,
        .r10 = (uint64_t)optval,
        .r8 = optlen,
    };
    int ret = hypercall(&param);
    return ret;
}

void hp_exit(void)
{
    struct HypercallParam param = {
        .rax = __NR_exit,
    };
    hypercall(&param);
}

int hp_execve(const char *path, char *const argv[], char *const envp[])
{
    struct HypercallParam param = {
        .rax = __NR_execve,
        .rdi = (uint64_t)path,
        .rsi = (uint64_t)argv,
        .rdx = (uint64_t)envp,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_shmdt(const void *shmaddr)
{
    struct HypercallParam param = {
        .rax = __NR_shmdt,
        .rdi = (uint64_t)shmaddr,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_flock(int fd, int operation)
{
    struct HypercallParam param = {
        .rax = __NR_flock,
        .rdi = fd,
        .rsi = operation,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fsync(int fd)
{
    struct HypercallParam param = {
        .rax = __NR_fsync,
        .rdi = fd,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fdatasync(int fd)
{
    struct HypercallParam param = {
        .rax = __NR_fdatasync,
        .rdi = fd,
    };
    int ret = hypercall(&param);
    return ret;
}

long hp_getdents(unsigned int fd, void *dirp,
              unsigned int count) {
    struct HypercallParam param = {
        .rax = __NR_getdents,
        .rdi = fd,
        .rsi = (uint64_t)dirp,
        .rdx = count,
    };
    long ret = hypercall(&param);
    return ret;
}

char *hp_getcwd(char *buf, size_t size)
{
    struct HypercallParam param = {
        .rax = __NR_getcwd,
        .rdi = (uint64_t)buf,
        .rsi = size,
    };
    char *ret = (char *)hypercall(&param);
    return ret;
}

int hp_chdir(const char *__path)
{
    struct HypercallParam param = {
        .rax = __NR_chdir,
        .rdi = (uint64_t)__path,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fchdir(int fd)
{
    struct HypercallParam param = {
        .rax = __NR_fchdir,
        .rdi = fd,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_rename(const char *oldpath, const char *newpath)
{
    struct HypercallParam param = {
        .rax = __NR_rename,
        .rdi = (uint64_t)oldpath,
        .rsi = (uint64_t)newpath,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mkdir(const char *pathname, mode_t mode)
{
    struct HypercallParam param = {
        .rax = __NR_mkdir,
        .rdi = (uint64_t)pathname,
        .rsi = mode,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_rmdir(const char *pathname)
{
    struct HypercallParam param = {
        .rax = __NR_rmdir,
        .rdi = (uint64_t)pathname,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_creat(const char *pathname, mode_t mode)
{
    struct HypercallParam param = {
        .rax = __NR_creat,
        .rdi = (uint64_t)pathname,
        .rsi = mode,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_link(const char *oldpath, const char *newpath)
{
    struct HypercallParam param = {
        .rax = __NR_link,
        .rdi = (uint64_t)oldpath,
        .rsi = (uint64_t)newpath,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_unlink(const char *pathname)
{
    struct HypercallParam param = {
        .rax = __NR_unlink,
        .rdi = (uint64_t)pathname,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_symlink(const char *target, const char *linkpath)
{
    struct HypercallParam param = {
        .rax = __NR_symlink,
        .rdi = (uint64_t)target,
        .rsi = (uint64_t)linkpath,
    };
    int ret = hypercall(&param);
    return ret;
}

ssize_t hp_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    struct HypercallParam param = {
        .rax = __NR_readlink,
        .rdi = (uint64_t)pathname,
        .rsi = (uint64_t)buf,
        .rdx = bufsiz,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

int hp_chmod(const char *pathname, mode_t mode)
{
    struct HypercallParam param = {
        .rax = __NR_chmod,
        .rdi = (uint64_t)pathname,
        .rsi = mode,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fchmod(int fd, mode_t mode)
{
    struct HypercallParam param = {
        .rax = __NR_fchmod,
        .rdi = fd,
        .rsi = mode,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_chown(const char *pathname, uid_t owner, gid_t group)
{
    struct HypercallParam param = {
        .rax = __NR_chown,
        .rdi = (uint64_t)pathname,
        .rsi = owner,
        .rdx = group,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fchown(int fd, uid_t owner, gid_t group)
{
    struct HypercallParam param = {
        .rax = __NR_fchown,
        .rdi = fd,
        .rsi = owner,
        .rdx = group,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_lchown(const char *pathname, uid_t owner, gid_t group)
{
    struct HypercallParam param = {
        .rax = __NR_lchown,
        .rdi = (uint64_t)pathname,
        .rsi = owner,
        .rdx = group,
    };
    int ret = hypercall(&param);
    return ret;
}

__mode_t hp_umask(mode_t mask)
{
    struct HypercallParam param = {
        .rax = __NR_umask,
        .rdi = mask,
    };
    __mode_t ret = hypercall(&param);
    return ret;
}

int hp_getrlimit(int resource, struct rlimit *rlim)
{
    struct HypercallParam param = {
        .rax = __NR_getrlimit,
        .rdi = resource,
        .rsi = (uint64_t)rlim,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_getrusage(int who, struct rusage *usage)
{
    struct HypercallParam param = {
        .rax = __NR_getrusage,
        .rdi = who,
        .rsi = (uint64_t)usage,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_sysinfo(struct sysinfo *info)
{
    struct HypercallParam param = {
        .rax = __NR_sysinfo,
        .rdi = (uint64_t)info,
    };
    int ret = hypercall(&param);
    return ret;
}

clock_t hp_times(struct tms *buf)
{
    struct HypercallParam param = {
        .rax = __NR_times,
        .rdi = (uint64_t)buf,
    };
    clock_t ret = hypercall(&param);
    return ret;
}

__uid_t hp_getuid(void)
{
    struct HypercallParam param = {
        .rax = __NR_getuid,
    };
    __uid_t ret = hypercall(&param);
    return ret;
}

void hp_syslog(int type, char *bufp, int len)
{
    struct HypercallParam param = {
        .rax = __NR_syslog,
        .rdi = type,
        .rsi = (uint64_t)bufp,
        .rdx = len,
    };
    hypercall(&param);
}

__gid_t hp_getgid(void)
{
    struct HypercallParam param = {
        .rax = __NR_getgid,
    };
    __gid_t ret = hypercall(&param);
    return ret;
}

int hp_setuid(uid_t uid)
{
    struct HypercallParam param = {
        .rax = __NR_setuid,
        .rdi = uid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setgid(gid_t gid)
{
    struct HypercallParam param = {
        .rax = __NR_setgid,
        .rdi = gid,
    };
    int ret = hypercall(&param);
    return ret;
}

__uid_t hp_geteuid(void)
{
    struct HypercallParam param = {
        .rax = __NR_geteuid,
    };
    __uid_t ret = hypercall(&param);
    return ret;
}

__gid_t hp_getegid(void)
{
    struct HypercallParam param = {
        .rax = __NR_getegid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setpgid(pid_t pid, pid_t pgid)
{
    struct HypercallParam param = {
        .rax = __NR_setpgid,
        .rdi = pid,
        .rsi = pgid,
    };
    int ret = hypercall(&param);
    return ret;
}

pid_t hp_getppid(void)
{
    struct HypercallParam param = {
        .rax = __NR_getppid,
    };
    pid_t ppid = hypercall(&param);
    return ppid;
}

pid_t hp_getpgrp(void)
{
    struct HypercallParam param = {
        .rax = __NR_getpgrp,
    };
    pid_t pgrp = hypercall(&param);
    return pgrp;
}

pid_t hp_setsid(void)
{
    struct HypercallParam param = {
        .rax = __NR_setsid,
    };
    pid_t sid = hypercall(&param);
    return sid;
}

int hp_setreuid(uid_t ruid, uid_t euid)
{
    struct HypercallParam param = {
        .rax = __NR_setreuid,
        .rdi = ruid,
        .rsi = euid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setregid(gid_t rgid, gid_t egid)
{
    struct HypercallParam param = {
        .rax = __NR_setregid,
        .rdi = rgid,
        .rsi = egid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_getgroups(int size, gid_t list[])
{
    struct HypercallParam param = {
        .rax = __NR_getgroups,
        .rdi = size,
        .rsi = (uint64_t)list,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setgroups(size_t size, const gid_t *list)
{
    struct HypercallParam param = {
        .rax = __NR_setgroups,
        .rdi = size,
        .rsi = (uint64_t)list,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    struct HypercallParam param = {
        .rax = __NR_setresuid,
        .rdi = ruid,
        .rsi = euid,
        .rdx = suid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    struct HypercallParam param = {
        .rax = __NR_getresuid,
        .rdi = (uint64_t)ruid,
        .rsi = (uint64_t)euid,
        .rdx = (uint64_t)suid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
    struct HypercallParam param = {
        .rax = __NR_setresgid,
        .rdi = rgid,
        .rsi = egid,
        .rdx = sgid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    struct HypercallParam param = {
        .rax = __NR_getresgid,
        .rdi = (uint64_t)rgid,
        .rsi = (uint64_t)egid,
        .rdx = (uint64_t)sgid,
    };
    int ret = hypercall(&param);
    return ret;
}

pid_t hp_getpgid(pid_t pid)
{
    struct HypercallParam param = {
        .rax = __NR_getpgid,
        .rdi = pid,
    };
    pid_t pgid = hypercall(&param);
    return pgid;
}

int hp_setfsuid(uid_t fsuid)
{
    struct HypercallParam param = {
        .rax = __NR_setfsuid,
        .rdi = fsuid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setfsgid(gid_t fsgid)
{
    struct HypercallParam param = {
        .rax = __NR_setfsgid,
        .rdi = fsgid,
    };
    int ret = hypercall(&param);
    return ret;
}

pid_t hp_getsid(pid_t pid)
{
    struct HypercallParam param = {
        .rax = __NR_getsid,
        .rdi = pid,
    };
    pid_t sid = hypercall(&param);
    return sid;
}

int hp_capget(cap_user_header_t header, cap_user_data_t dataptr)
{
    struct HypercallParam param = {
        .rax = __NR_capget,
        .rdi = (uint64_t)header,
        .rsi = (uint64_t)dataptr,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_capset(cap_user_header_t header, const cap_user_data_t data)
{
    struct HypercallParam param = {
        .rax = __NR_capset,
        .rdi = (uint64_t)header,
        .rsi = (uint64_t)data,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_rt_sigpending(sigset_t *set, size_t sigsetsize)
{
    struct HypercallParam param = {
        .rax = __NR_rt_sigpending,
        .rdi = (uint64_t)set,
        .rsi = sigsetsize,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
                       const struct timespec *uts, size_t sigsetsize)
{
    struct HypercallParam param = {
        .rax = __NR_rt_sigtimedwait,
        .rdi = (uint64_t)uthese,
        .rsi = (uint64_t)uinfo,
        .rdx = (uint64_t)uts,
        .r10 = sigsetsize,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *uinfo)
{
    struct HypercallParam param = {
        .rax = __NR_rt_sigqueueinfo,
        .rdi = pid,
        .rsi = sig,
        .rdx = (uint64_t)uinfo,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_rt_sigsuspend(const sigset_t *unewset, size_t sigsetsize)
{
    struct HypercallParam param = {
        .rax = __NR_rt_sigsuspend,
        .rdi = (uint64_t)unewset,
        .rsi = sigsetsize,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_sigaltstack(const stack_t *uss, stack_t *uoss)
{
    struct HypercallParam param = {
        .rax = __NR_sigaltstack,
        .rdi = (uint64_t)uss,
        .rsi = (uint64_t)uoss,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_utime(const char *filename, const struct utimbuf *times)
{
    struct HypercallParam param = {
        .rax = __NR_utime,
        .rdi = (uint64_t)filename,
        .rsi = (uint64_t)times,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mknod(const char *pathname, mode_t mode, dev_t dev)
{
    struct HypercallParam param = {
        .rax = __NR_mknod,
        .rdi = (uint64_t)pathname,
        .rsi = mode,
        .rdx = dev,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_uselib(const char *library)
{
    struct HypercallParam param = {
        .rax = __NR_uselib,
        .rdi = (uint64_t)library,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_statfs(const char *pathname, struct statfs *buf)
{
    struct HypercallParam param = {
        .rax = __NR_statfs,
        .rdi = (uint64_t)pathname,
        .rsi = (uint64_t)buf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fstatfs(int fd, struct statfs *buf)
{
    struct HypercallParam param = {
        .rax = __NR_fstatfs,
        .rdi = fd,
        .rsi = (uint64_t)buf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_sysfs(int option, unsigned long arg1, unsigned long arg2)
{
    struct HypercallParam param = {
        .rax = __NR_sysfs,
        .rdi = option,
        .rsi = arg1,
        .rdx = arg2,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_getpriority(__priority_which_t __which, id_t __who)
{
    struct HypercallParam param = {
        .rax = __NR_getpriority,
        .rdi = __which,
        .rsi = __who,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setpriority(__priority_which_t __which, id_t __who, int __prio)
{
    struct HypercallParam param = {
        .rax = __NR_setpriority,
        .rdi = __which,
        .rsi = __who,
        .rdx = __prio,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_sched_setparam(pid_t pid, const struct sched_param *param)
{
    struct HypercallParam hp = {
        .rax = __NR_sched_setparam,
        .rdi = pid,
        .rsi = (uint64_t)param,
    };
    int ret = hypercall(&hp);
    return ret;
}

int hp_sched_getparam(pid_t pid, struct sched_param *param)
{
    struct HypercallParam hp = {
        .rax = __NR_sched_getparam,
        .rdi = pid,
        .rsi = (uint64_t)param,
    };
    int ret = hypercall(&hp);
    return ret;
}

int hp_sched_setscheduler(pid_t pid, int policy,
                          const struct sched_param *param)
{
    struct HypercallParam hp = {
        .rax = __NR_sched_setscheduler,
        .rdi = pid,
        .rsi = policy,
        .rdx = (uint64_t)param,
    };
    int ret = hypercall(&hp);
    return ret;
}

int hp_sched_getscheduler(pid_t pid)
{
    struct HypercallParam hp = {
        .rax = __NR_sched_getscheduler,
        .rdi = pid,
    };
    int ret = hypercall(&hp);
    return ret;
}

int hp_sched_get_priority_max(int policy)
{
    struct HypercallParam hp = {
        .rax = __NR_sched_get_priority_max,
        .rdi = policy,
    };
    int ret = hypercall(&hp);
    return ret;
}

int hp_sched_get_priority_min(int policy)
{
    struct HypercallParam hp = {
        .rax = __NR_sched_get_priority_min,
        .rdi = policy,
    };
    int ret = hypercall(&hp);
    return ret;
}

int hp_sched_rr_get_interval(pid_t pid, struct timespec *tp)
{
    struct HypercallParam hp = {
        .rax = __NR_sched_rr_get_interval,
        .rdi = pid,
        .rsi = (uint64_t)tp,
    };
    int ret = hypercall(&hp);
    return ret;
}

int hp_mlock(const void *addr, size_t len)
{
    struct HypercallParam param = {
        .rax = __NR_mlock,
        .rdi = (uint64_t)addr,
        .rsi = len,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_munlock(const void *addr, size_t len)
{
    struct HypercallParam param = {
        .rax = __NR_munlock,
        .rdi = (uint64_t)addr,
        .rsi = len,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mlockall(int flags)
{
    struct HypercallParam param = {
        .rax = __NR_mlockall,
        .rdi = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_munlockall(void)
{
    struct HypercallParam param = {
        .rax = __NR_munlockall,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_vhangup(void)
{
    struct HypercallParam param = {
        .rax = __NR_vhangup,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_modify_ldt(int func, void *ptr, unsigned long bytecount)
{
    struct HypercallParam param = {
        .rax = __NR_modify_ldt,
        .rdi = func,
        .rsi = (uint64_t)ptr,
        .rdx = bytecount,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_pivot_root(const char *new_root, const char *put_old)
{
    struct HypercallParam param = {
        .rax = __NR_pivot_root,
        .rdi = (uint64_t)new_root,
        .rsi = (uint64_t)put_old,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp__sysctl(struct __sysctl_args *args)
{
    struct HypercallParam param = {
        .rax = __NR__sysctl,
        .rdi = (uint64_t)args,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_arch_prctl(int code, unsigned long addr)
{
    struct HypercallParam param = {
        .rax = __NR_arch_prctl,
        .rdi = code,
        .rsi = addr,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_adjtimex(struct timex *buf)
{
    struct HypercallParam param = {
        .rax = __NR_adjtimex,
        .rdi = (uint64_t)buf,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setrlimit(int resource, const struct rlimit *rlim)
{
    struct HypercallParam param = {
        .rax = __NR_setrlimit,
        .rdi = resource,
        .rsi = (uint64_t)rlim,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_chroot(const char *pathname)
{
    struct HypercallParam param = {
        .rax = __NR_chroot,
        .rdi = (uint64_t)pathname,
    };
    int ret = hypercall(&param);
    return ret;
}

void hp_sync(void)
{
    struct HypercallParam param = {
        .rax = __NR_sync,
    };
    hypercall(&param);
}

int hp_acct(const char *filename)
{
    struct HypercallParam param = {
        .rax = __NR_acct,
        .rdi = (uint64_t)filename,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_settimeofday(const struct timeval *tv, const struct timezone *tz)
{
    struct HypercallParam param = {
        .rax = __NR_settimeofday,
        .rdi = (uint64_t)tv,
        .rsi = (uint64_t)tz,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mount(const char *source, const char *target,
             const char *filesystemtype, unsigned long mountflags,
             const void *data)
{
    struct HypercallParam param = {
        .rax = __NR_mount,
        .rdi = (uint64_t)source,
        .rsi = (uint64_t)target,
        .rdx = (uint64_t)filesystemtype,
        .r10 = mountflags,
        .r8 = (uint64_t)data,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_umount2(const char *target, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_umount2,
        .rdi = (uint64_t)target,
        .rsi = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_swapon(const char *path, int swapflags)
{
    struct HypercallParam param = {
        .rax = __NR_swapon,
        .rdi = (uint64_t)path,
        .rsi = swapflags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_swapoff(const char *path)
{
    struct HypercallParam param = {
        .rax = __NR_swapoff,
        .rdi = (uint64_t)path,
    };
    int ret = hypercall(&param);
    return ret;
}

void hp_reboot(int magic1, int magic2, unsigned int cmd, void *arg)
{
    struct HypercallParam param = {
        .rax = __NR_reboot,
        .rdi = magic1,
        .rsi = magic2,
        .rdx = cmd,
        .r10 = (uint64_t)arg,
    };
    hypercall(&param);
}

int hp_sethostname(const char *name, size_t len)
{
    struct HypercallParam param = {
        .rax = __NR_sethostname,
        .rdi = (uint64_t)name,
        .rsi = len,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setdomainname(const char *name, size_t len)
{
    struct HypercallParam param = {
        .rax = __NR_setdomainname,
        .rdi = (uint64_t)name,
        .rsi = len,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_iopl(int level)
{
    struct HypercallParam param = {
        .rax = __NR_iopl,
        .rdi = level,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_ioperm(unsigned long from, unsigned long num, int turn_on)
{
    struct HypercallParam param = {
        .rax = __NR_ioperm,
        .rdi = from,
        .rsi = num,
        .rdx = turn_on,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_create_module(const char *name, size_t size)
{
    struct HypercallParam param = {
        .rax = __NR_create_module,
        .rdi = (uint64_t)name,
        .rsi = size,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_init_module(void *module_image, unsigned long len,
                   const char *param_values)
{
    struct HypercallParam param = {
        .rax = __NR_init_module,
        .rdi = (uint64_t)module_image,
        .rsi = len,
        .rdx = (uint64_t)param_values,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_delete_module(const char *name, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_delete_module,
        .rdi = (uint64_t)name,
        .rsi = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_query_module(const char *name, int which, void *buf, size_t bufsize,
                    size_t *ret)
{
    struct HypercallParam param = {
        .rax = __NR_query_module,
        .rdi = (uint64_t)name,
        .rsi = which,
        .rdx = (uint64_t)buf,
        .r10 = bufsize,
        .r8 = (uint64_t)ret,
    };
    int rc = hypercall(&param);
    return rc;
}

int hp_quotactl(int cmd, const char *special, int id, caddr_t addr)
{
    struct HypercallParam param = {
        .rax = __NR_quotactl,
        .rdi = cmd,
        .rsi = (uint64_t)special,
        .rdx = id,
        .r10 = (uint64_t)addr,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_gettid(void)
{
    struct HypercallParam param = {
        .rax = __NR_gettid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_setxattr(const char *path, const char *name, const void *value,
                size_t size, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_setxattr,
        .rdi = (uint64_t)path,
        .rsi = (uint64_t)name,
        .rdx = (uint64_t)value,
        .r10 = size,
        .r8 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_lsetxattr(const char *path, const char *name, const void *value,
                 size_t size, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_lsetxattr,
        .rdi = (uint64_t)path,
        .rsi = (uint64_t)name,
        .rdx = (uint64_t)value,
        .r10 = size,
        .r8 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fsetxattr(int fd, const char *name, const void *value, size_t size,
                 int flags)
{
    struct HypercallParam param = {
        .rax = __NR_fsetxattr,
        .rdi = fd,
        .rsi = (uint64_t)name,
        .rdx = (uint64_t)value,
        .r10 = size,
        .r8 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

ssize_t hp_getxattr(const char *path, const char *name, void *value, size_t size)
{
    struct HypercallParam param = {
        .rax = __NR_getxattr,
        .rdi = (uint64_t)path,
        .rsi = (uint64_t)name,
        .rdx = (uint64_t)value,
        .r10 = size,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

ssize_t hp_lgetxattr(const char *path, const char *name, void *value, size_t size)
{
    struct HypercallParam param = {
        .rax = __NR_lgetxattr,
        .rdi = (uint64_t)path,
        .rsi = (uint64_t)name,
        .rdx = (uint64_t)value,
        .r10 = size,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

ssize_t hp_fgetxattr(int fd, const char *name, void *value, size_t size)
{
    struct HypercallParam param = {
        .rax = __NR_fgetxattr,
        .rdi = fd,
        .rsi = (uint64_t)name,
        .rdx = (uint64_t)value,
        .r10 = size,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

ssize_t hp_listxattr(const char *path, char *list, size_t size)
{
    struct HypercallParam param = {
        .rax = __NR_listxattr,
        .rdi = (uint64_t)path,
        .rsi = (uint64_t)list,
        .rdx = size,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

ssize_t hp_llistxattr(const char *path, char *list, size_t size)
{
    struct HypercallParam param = {
        .rax = __NR_llistxattr,
        .rdi = (uint64_t)path,
        .rsi = (uint64_t)list,
        .rdx = size,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

ssize_t hp_flistxattr(int fd, char *list, size_t size)
{
    struct HypercallParam param = {
        .rax = __NR_flistxattr,
        .rdi = fd,
        .rsi = (uint64_t)list,
        .rdx = size,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

int hp_removexattr(const char *path, const char *name)
{
    struct HypercallParam param = {
        .rax = __NR_removexattr,
        .rdi = (uint64_t)path,
        .rsi = (uint64_t)name,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_lremovexattr(const char *path, const char *name)
{
    struct HypercallParam param = {
        .rax = __NR_lremovexattr,
        .rdi = (uint64_t)path,
        .rsi = (uint64_t)name,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fremovexattr(int fd, const char *name)
{
    struct HypercallParam param = {
        .rax = __NR_fremovexattr,
        .rdi = fd,
        .rsi = (uint64_t)name,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_tkill(int tid, int sig)
{
    struct HypercallParam param = {
        .rax = __NR_tkill,
        .rdi = tid,
        .rsi = sig,
    };
    int ret = hypercall(&param);
    return ret;
}

time_t hp_time(time_t *tloc)
{
    struct HypercallParam param = {
        .rax = __NR_time,
        .rdi = (uint64_t)tloc,
    };
    time_t ret = hypercall(&param);
    return ret;
}

int hp_futex(int *uaddr, int op, int val, const struct timespec *timeout,
             int *uaddr2, int val3)
{
    struct HypercallParam param = {
        .rax = __NR_futex,
        .rdi = (uint64_t)uaddr,
        .rsi = op,
        .rdx = val,
        .r10 = (uint64_t)timeout,
        .r8 = (uint64_t)uaddr2,
        .r9 = val3,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_sched_setaffinity(pid_t pid, size_t cpusetsize,
                         const cpu_set_t *mask)
{
    struct HypercallParam param = {
        .rax = __NR_sched_setaffinity,
        .rdi = pid,
        .rsi = cpusetsize,
        .rdx = (uint64_t)mask,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_sched_getaffinity(pid_t pid, size_t cpusetsize,
                         cpu_set_t *mask)
{
    struct HypercallParam param = {
        .rax = __NR_sched_getaffinity,
        .rdi = pid,
        .rsi = cpusetsize,
        .rdx = (uint64_t)mask,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_set_thread_area(struct user_desc *u_info)
{
    struct HypercallParam param = {
        .rax = __NR_set_thread_area,
        .rdi = (uint64_t)u_info,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_io_setup(unsigned nr_reqs, aio_context_t *ctxp)
{
    struct HypercallParam param = {
        .rax = __NR_io_setup,
        .rdi = nr_reqs,
        .rsi = (uint64_t)ctxp,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_io_destroy(aio_context_t ctx)
{
    struct HypercallParam param = {
        .rax = __NR_io_destroy,
        .rdi = ctx,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_io_getevents(aio_context_t ctx_id, long min_nr, long nr,
                    struct io_event *events, struct timespec *timeout)
{
    struct HypercallParam param = {
        .rax = __NR_io_getevents,
        .rdi = ctx_id,
        .rsi = min_nr,
        .rdx = nr,
        .r10 = (uint64_t)events,
        .r8 = (uint64_t)timeout,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp)
{
    struct HypercallParam param = {
        .rax = __NR_io_submit,
        .rdi = ctx_id,
        .rsi = nr,
        .rdx = (uint64_t)iocbpp,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_io_cancel(aio_context_t ctx_id, struct iocb *iocb,
                 struct io_event *result)
{
    struct HypercallParam param = {
        .rax = __NR_io_cancel,
        .rdi = ctx_id,
        .rsi = (uint64_t)iocb,
        .rdx = (uint64_t)result,
    };
    int ret = hypercall(&param);
    return ret;
}
int hp_get_thread_area(struct user_desc *u_info)
{
    struct HypercallParam param = {
        .rax = __NR_get_thread_area,
        .rdi = (uint64_t)u_info,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_lookup_dcookie(u64 cookie64, char *buf, size_t len)
{
    struct HypercallParam param = {
        .rax = __NR_lookup_dcookie,
        .rdi = cookie64,
        .rsi = (uint64_t)buf,
        .rdx = len,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_epoll_create(int size)
{
    struct HypercallParam param = {
        .rax = __NR_epoll_create,
        .rdi = size,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_epoll_ctl_old(int epfd, int op, int fd, struct epoll_event *event)
{
    struct HypercallParam param = {
        .rax = __NR_epoll_ctl_old,
        .rdi = epfd,
        .rsi = op,
        .rdx = fd,
        .r10 = (uint64_t)event,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_epoll_wait_old(int epfd, struct epoll_event *events, int maxevents,
                      int timeout)
{
    struct HypercallParam param = {
        .rax = __NR_epoll_wait_old,
        .rdi = epfd,
        .rsi = (uint64_t)events,
        .rdx = maxevents,
        .r10 = timeout,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_remap_file_pages(void *start, size_t size, int prot, ssize_t pgoff,
                        int flags)
{
    struct HypercallParam param = {
        .rax = __NR_remap_file_pages,
        .rdi = (uint64_t)start,
        .rsi = size,
        .rdx = prot,
        .r10 = pgoff,
        .r8 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

ssize_t hp_getdents64(int fd, void *dirp, size_t count)
{
    struct HypercallParam param = {
        .rax = __NR_getdents64,
        .rdi = fd,
        .rsi = (uint64_t)dirp,
        .rdx = count,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

int hp_set_tid_address(int *tidptr)
{
    struct HypercallParam param = {
        .rax = __NR_set_tid_address,
        .rdi = (uint64_t)tidptr,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_restart_syscall(void)
{
    struct HypercallParam param = {
        .rax = __NR_restart_syscall,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_semtimedop(int semid, struct sembuf *sops, unsigned nsops,
                  const struct timespec *timeout)
{
    struct HypercallParam param = {
        .rax = __NR_semtimedop,
        .rdi = semid,
        .rsi = (uint64_t)sops,
        .rdx = nsops,
        .r10 = (uint64_t)timeout,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fadvise64(int fd, loff_t offset, size_t len, int advice)
{
    struct HypercallParam param = {
        .rax = __NR_fadvise64,
        .rdi = fd,
        .rsi = offset,
        .rdx = len,
        .r10 = advice,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_timer_create(clockid_t which_clock, struct sigevent *timer_event_spec,
                    timer_t *created_timer_id)
{
    struct HypercallParam param = {
        .rax = __NR_timer_create,
        .rdi = which_clock,
        .rsi = (uint64_t)timer_event_spec,
        .rdx = (uint64_t)created_timer_id,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_timer_settime(timer_t timer_id, int flags,
                     const struct itimerspec *new_setting,
                     struct itimerspec *old_setting)
{
    struct HypercallParam param = {
        .rax = __NR_timer_settime,
        .rdi = (uint64_t)timer_id,
        .rsi = (uint64_t)flags,
        .rdx = (uint64_t)new_setting,
        .r10 = (uint64_t)old_setting,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_timer_gettime(timer_t timer_id, struct itimerspec *setting)
{
    struct HypercallParam param = {
        .rax = __NR_timer_gettime,
        .rdi = (uint64_t)timer_id,
        .rsi = (uint64_t)setting,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_timer_getoverrun(timer_t timer_id)
{
    struct HypercallParam param = {
        .rax = __NR_timer_getoverrun,
        .rdi = (uint64_t)timer_id,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_timer_delete(timer_t timer_id)
{
    struct HypercallParam param = {
        .rax = __NR_timer_delete,
        .rdi = (uint64_t)timer_id,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_clock_settime(clockid_t which_clock, const struct timespec *tp)
{
    struct HypercallParam param = {
        .rax = __NR_clock_settime,
        .rdi = which_clock,
        .rsi = (uint64_t)tp,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_clock_gettime(clockid_t which_clock, struct timespec *tp)
{
    struct HypercallParam param = {
        .rax = __NR_clock_gettime,
        .rdi = which_clock,
        .rsi = (uint64_t)tp,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_clock_getres(clockid_t which_clock, struct timespec *tp)
{
    struct HypercallParam param = {
        .rax = __NR_clock_getres,
        .rdi = which_clock,
        .rsi = (uint64_t)tp,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_clock_nanosleep(clockid_t which_clock, int flags,
                       const struct timespec *rqtp,
                       struct timespec *rmtp)
{
    struct HypercallParam param = {
        .rax = __NR_clock_nanosleep,
        .rdi = which_clock,
        .rsi = flags,
        .rdx = (uint64_t)rqtp,
        .r10 = (uint64_t)rmtp,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_exit_group(int status)
{
    struct HypercallParam param = {
        .rax = __NR_exit_group,
        .rdi = status,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                  int timeout)
{
    struct HypercallParam param = {
        .rax = __NR_epoll_wait,
        .rdi = epfd,
        .rsi = (uint64_t)events,
        .rdx = maxevents,
        .r10 = timeout,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    struct HypercallParam param = {
        .rax = __NR_epoll_ctl,
        .rdi = epfd,
        .rsi = op,
        .rdx = fd,
        .r10 = (uint64_t)event,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_tgkill(int tgid, int tid, int sig)
{
    struct HypercallParam param = {
        .rax = __NR_tgkill,
        .rdi = tgid,
        .rsi = tid,
        .rdx = sig,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_utimes(const char *__file, const struct timeval __tvp[2])
{
    struct HypercallParam param = {
        .rax = __NR_utimes,
        .rdi = (uint64_t)__file,
        .rsi = (uint64_t)__tvp,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_vserver(void)
{
    struct HypercallParam param = {
        .rax = __NR_vserver,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mbind(void *addr, unsigned long len, int mode,
             unsigned long *nmask, unsigned long maxnode,
             unsigned flags)
{
    struct HypercallParam param = {
        .rax = __NR_mbind,
        .rdi = (uint64_t)addr,
        .rsi = len,
        .rdx = mode,
        .r10 = (uint64_t)nmask,
        .r8 = maxnode,
        .r9 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_set_mempolicy(int mode, unsigned long *nmask,
                     unsigned long maxnode)
{
    struct HypercallParam param = {
        .rax = __NR_set_mempolicy,
        .rdi = mode,
        .rsi = (uint64_t)nmask,
        .rdx = maxnode,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_get_mempolicy(int *policy, unsigned long *nmask,
                     unsigned long maxnode, void *addr,
                     unsigned long flags)
{
    struct HypercallParam param = {
        .rax = __NR_get_mempolicy,
        .rdi = (uint64_t)policy,
        .rsi = (uint64_t)nmask,
        .rdx = maxnode,
        .r10 = (uint64_t)addr,
        .r8 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mq_unlink(const char *name)
{
    struct HypercallParam param = {
        .rax = __NR_mq_unlink,
        .rdi = (uint64_t)name,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mq_timedsend(mqd_t mqdes, const char *msg_ptr,
                    size_t msg_len, unsigned int msg_prio,
                    const struct timespec *abs_timeout)
{
    struct HypercallParam param = {
        .rax = __NR_mq_timedsend,
        .rdi = mqdes,
        .rsi = (uint64_t)msg_ptr,
        .rdx = msg_len,
        .r10 = msg_prio,
        .r8 = (uint64_t)abs_timeout,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

ssize_t hp_mq_timedreceive(mqd_t mqdes, char *msg_ptr,
                          size_t msg_len, unsigned int *msg_prio,
                          const struct timespec *abs_timeout)
{
    struct HypercallParam param = {
        .rax = __NR_mq_timedreceive,
        .rdi = mqdes,
        .rsi = (uint64_t)msg_ptr,
        .rdx = msg_len,
        .r10 = (uint64_t)msg_prio,
        .r8 = (uint64_t)abs_timeout,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

int hp_mq_notify(mqd_t mqdes, const struct sigevent *notification)
{
    struct HypercallParam param = {
        .rax = __NR_mq_notify,
        .rdi = mqdes,
        .rsi = (uint64_t)notification,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mq_getsetattr(mqd_t mqdes, const struct mq_attr *mqstat,
                     struct mq_attr *omqstat)
{
    struct HypercallParam param = {
        .rax = __NR_mq_getsetattr,
        .rdi = mqdes,
        .rsi = (uint64_t)mqstat,
        .rdx = (uint64_t)omqstat,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_kexec_load(unsigned long entry, unsigned long nr_segments,
                  struct kexec_segment *segments, unsigned long flags)
{
    struct HypercallParam param = {
        .rax = __NR_kexec_load,
        .rdi = entry,
        .rsi = nr_segments,
        .rdx = (uint64_t)segments,
        .r10 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_add_key(const char *_type, const char *_description,
               const void *_payload, size_t plen, key_serial_t destringid)
{
    struct HypercallParam param = {
        .rax = __NR_add_key,
        .rdi = (uint64_t)_type,
        .rsi = (uint64_t)_description,
        .rdx = (uint64_t)_payload,
        .r10 = plen,
        .r8 = destringid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_request_key(const char *_type, const char *_description,
                   const char *_callout_info, key_serial_t destringid)
{
    struct HypercallParam param = {
        .rax = __NR_request_key,
        .rdi = (uint64_t)_type,
        .rsi = (uint64_t)_description,
        .rdx = (uint64_t)_callout_info,
        .r10 = destringid,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_ioprio_set(int which, int who, int ioprio)
{
    struct HypercallParam param = {
        .rax = __NR_ioprio_set,
        .rdi = which,
        .rsi = who,
        .rdx = ioprio,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_ioprio_get(int which, int who)
{
    struct HypercallParam param = {
        .rax = __NR_ioprio_get,
        .rdi = which,
        .rsi = who,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_inotify_init(void)
{
    struct HypercallParam param = {
        .rax = __NR_inotify_init,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_inotify_add_watch(int fd, const char *path, uint32_t mask)
{
    struct HypercallParam param = {
        .rax = __NR_inotify_add_watch,
        .rdi = fd,
        .rsi = (uint64_t)path,
        .rdx = mask,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_inotify_rm_watch(int fd, __s32 wd)
{
    struct HypercallParam param = {
        .rax = __NR_inotify_rm_watch,
        .rdi = fd,
        .rsi = wd,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_migrate_pages(pid_t pid, unsigned long maxnode,
                     const unsigned long *old_nodes,
                     const unsigned long *new_nodes)
{
    struct HypercallParam param = {
        .rax = __NR_migrate_pages,
        .rdi = pid,
        .rsi = maxnode,
        .rdx = (uint64_t)old_nodes,
        .r10 = (uint64_t)new_nodes,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mkdirat(int dfd, const char *pathname, mode_t mode)
{
    struct HypercallParam param = {
        .rax = __NR_mkdirat,
        .rdi = dfd,
        .rsi = (uint64_t)pathname,
        .rdx = mode,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_mknodat(int dfd, const char *filename, mode_t mode, dev_t dev)
{
    struct HypercallParam param = {
        .rax = __NR_mknodat,
        .rdi = dfd,
        .rsi = (uint64_t)filename,
        .rdx = mode,
        .r10 = dev,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fchownat(int dfd, const char *filename, uid_t user, gid_t group,
                int flag)
{
    struct HypercallParam param = {
        .rax = __NR_fchownat,
        .rdi = dfd,
        .rsi = (uint64_t)filename,
        .rdx = user,
        .r10 = group,
        .r8 = flag,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_futimesat(int dirfd, const char *pathname,
                 const struct timeval times[2])
{
    struct HypercallParam param = {
        .rax = __NR_futimesat,
        .rdi = dirfd,
        .rsi = (uint64_t)pathname,
        .rdx = (uint64_t)utimes,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_newfstatat(int dfd, const char *filename, struct stat *statbuf,
                  int flag)
{
    struct HypercallParam param = {
        .rax = __NR_newfstatat,
        .rdi = dfd,
        .rsi = (uint64_t)filename,
        .rdx = (uint64_t)statbuf,
        .r10 = flag,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_unlinkat(int dfd, const char *pathname, int flag)
{
    struct HypercallParam param = {
        .rax = __NR_unlinkat,
        .rdi = dfd,
        .rsi = (uint64_t)pathname,
        .rdx = flag,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_renameat(int olddfd, const char *oldname, int newdfd,
                const char *newname)
{
    struct HypercallParam param = {
        .rax = __NR_renameat,
        .rdi = olddfd,
        .rsi = (uint64_t)oldname,
        .rdx = newdfd,
        .r10 = (uint64_t)newname,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_linkat(int olddfd, const char *oldname, int newdfd,
              const char *newname, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_linkat,
        .rdi = olddfd,
        .rsi = (uint64_t)oldname,
        .rdx = newdfd,
        .r10 = (uint64_t)newname,
        .r8 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_symlinkat(const char *oldname, int newdfd, const char *newname)
{
    struct HypercallParam param = {
        .rax = __NR_symlinkat,
        .rdi = (uint64_t)oldname,
        .rsi = newdfd,
        .rdx = (uint64_t)newname,
    };
    int ret = hypercall(&param);
    return ret;
}

ssize_t hp_readlinkat(int dfd, const char *pathname, char *buf, size_t bufsiz)
{
    struct HypercallParam param = {
        .rax = __NR_readlinkat,
        .rdi = dfd,
        .rsi = (uint64_t)pathname,
        .rdx = (uint64_t)buf,
        .r10 = bufsiz,
    };
    ssize_t ret = hypercall(&param);
    return ret;
}

int hp_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_fchmodat,
        .rdi = dirfd,
        .rsi = (uint64_t)pathname,
        .rdx = mode,
        .r10 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_faccessat(int __fd, const char *__file, int __type, int __flag)
{
    struct HypercallParam param = {
        .rax = __NR_faccessat,
        .rdi = __fd,
        .rsi = (uint64_t)__file,
        .rdx = __type,
        .r10 = __flag,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_pselect6(int nfds, fd_set *readfds, fd_set *writefds,
                fd_set *exceptfds, struct timespec *timeout,
                void *sigmask)
{
    struct HypercallParam param = {
        .rax = __NR_pselect6,
        .rdi = nfds,
        .rsi = (uint64_t)readfds,
        .rdx = (uint64_t)writefds,
        .r10 = (uint64_t)exceptfds,
        .r8 = (uint64_t)timeout,
        .r9 = (uint64_t)sigmask,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_ppoll(struct pollfd *fds, nfds_t nfds,
             const struct timespec *tmo_p, const sigset_t *sigmask)
{
    struct HypercallParam param = {
        .rax = __NR_ppoll,
        .rdi = (uint64_t)fds,
        .rsi = nfds,
        .rdx = (uint64_t)tmo_p,
        .r10 = (uint64_t)sigmask,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_unshare(int unshare_flags)
{
    struct HypercallParam param = {
        .rax = __NR_unshare,
        .rdi = unshare_flags,
    };
    int ret = hypercall(&param);
    return ret;
}

long hp_set_robust_list(struct robust_list_head *head, size_t len)
{
    struct HypercallParam param = {
        .rax = __NR_set_robust_list,
        .rdi = (uint64_t)head,
        .rsi = len,
    };
    long ret = hypercall(&param);
    return ret;
}

long hp_get_robust_list(int pid, struct robust_list_head **head_ptr,
                        size_t *len_ptr)
{
    struct HypercallParam param = {
        .rax = __NR_get_robust_list,
        .rdi = pid,
        .rsi = (uint64_t)head_ptr,
        .rdx = (uint64_t)len_ptr,
    };
    long ret = hypercall(&param);
    return ret;
}

int hp_splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
              size_t len, unsigned int flags)
{
    struct HypercallParam param = {
        .rax = __NR_splice,
        .rdi = fd_in,
        .rsi = (uint64_t)off_in,
        .rdx = fd_out,
        .r10 = (uint64_t)off_out,
        .r8 = len,
        .r9 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_tee(int fdin, int fdout, size_t len, unsigned int flags)
{
    struct HypercallParam param = {
        .rax = __NR_tee,
        .rdi = fdin,
        .rsi = fdout,
        .rdx = len,
        .r10 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_sync_file_range(int fd, loff_t offset, loff_t nbytes,
                       unsigned int flags)
{
    struct HypercallParam param = {
        .rax = __NR_sync_file_range,
        .rdi = fd,
        .rsi = offset,
        .rdx = nbytes,
        .r10 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs,
                unsigned int flags)
{
    struct HypercallParam param = {
        .rax = __NR_vmsplice,
        .rdi = fd,
        .rsi = (uint64_t)iov,
        .rdx = nr_segs,
        .r10 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_move_pages(pid_t pid, unsigned long nr_pages, void **pages,
                  const int *nodes, int *status, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_move_pages,
        .rdi = pid,
        .rsi = nr_pages,
        .rdx = (uint64_t)pages,
        .r10 = (uint64_t)nodes,
        .r8 = (uint64_t)status,
        .r9 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_utimensat(int dirfd, const char *pathname,
                 const struct timespec times[2], int flags)
{
    struct HypercallParam param = {
        .rax = __NR_utimensat,
        .rdi = dirfd,
        .rsi = (uint64_t)pathname,
        .rdx = (uint64_t)times,
        .r10 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_epoll_pwait(int epfd, struct epoll_event *events,
                   int maxevents, int timeout,
                   const sigset_t *sigmask)
{
    struct HypercallParam param = {
        .rax = __NR_epoll_pwait,
        .rdi = epfd,
        .rsi = (uint64_t)events,
        .rdx = maxevents,
        .r10 = timeout,
        .r8 = (uint64_t)sigmask,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_signalfd(int fd, const sigset_t *mask)
{
    struct HypercallParam param = {
        .rax = __NR_signalfd,
        .rdi = fd,
        .rsi = (uint64_t)mask,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_timerfd_create(int clockid, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_timerfd_create,
        .rdi = clockid,
        .rsi = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_eventfd(unsigned int initval, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_eventfd,
        .rdi = initval,
        .rsi = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fallocate(int fd, int mode, loff_t offset, loff_t len)
{
    struct HypercallParam param = {
        .rax = __NR_fallocate,
        .rdi = fd,
        .rsi = mode,
        .rdx = offset,
        .r10 = len,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_timerfd_settime(int ufd, int flags,
                       const struct itimerspec *utmr,
                       struct itimerspec *otmr)
{
    struct HypercallParam param = {
        .rax = __NR_timerfd_settime,
        .rdi = ufd,
        .rsi = flags,
        .rdx = (uint64_t)utmr,
        .r10 = (uint64_t)otmr,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_timerfd_gettime(int ufd, struct itimerspec *otmr)
{
    struct HypercallParam param = {
        .rax = __NR_timerfd_gettime,
        .rdi = ufd,
        .rsi = (uint64_t)otmr,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_accept4(int fd, struct sockaddr *upeer_sockaddr, socklen_t *upeer_addrlen, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_accept4,
        .rdi = fd,
        .rsi = (uint64_t)upeer_sockaddr,
        .rdx = (uint64_t)upeer_addrlen,
        .r10 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_signalfd4(int fd, const sigset_t *mask, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_signalfd4,
        .rdi = fd,
        .rsi = (uint64_t)mask,
        .rdx = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_eventfd2(unsigned int count, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_eventfd2,
        .rdi = count,
        .rsi = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_epoll_create1(int flags)
{
    struct HypercallParam param = {
        .rax = __NR_epoll_create1,
        .rdi = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_dup3(int oldfd, int newfd, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_dup3,
        .rdi = oldfd,
        .rsi = newfd,
        .rdx = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_pipe2(int pipefd[2], int flags)
{
    struct HypercallParam param = {
        .rax = __NR_pipe2,
        .rdi = (uint64_t)pipefd,
        .rsi = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_inotify_init1(int flags)
{
    struct HypercallParam param = {
        .rax = __NR_inotify_init1,
        .rdi = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
               off_t offset)
{
    struct HypercallParam param = {
        .rax = __NR_preadv,
        .rdi = fd,
        .rsi = (uint64_t)iov,
        .rdx = iovcnt,
        .r10 = offset,
    };
    int ret = hypercall(&param);
    return ret;
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt,
                off_t offset)
{
    struct HypercallParam param = {
        .rax = __NR_pwritev,
        .rdi = fd,
        .rsi = (uint64_t)iov,
        .rdx = iovcnt,
        .r10 = offset,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo)
{
    struct HypercallParam param = {
        .rax = __NR_rt_tgsigqueueinfo,
        .rdi = tgid,
        .rsi = tid,
        .rdx = sig,
        .r10 = (uint64_t)uinfo,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_perf_event_open(struct perf_event_attr *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    struct HypercallParam param = {
        .rax = __NR_perf_event_open,
        .rdi = (uint64_t)attr_uptr,
        .rsi = pid,
        .rdx = cpu,
        .r10 = group_fd,
        .r8 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                int flags, struct timespec *timeout)
{
    struct HypercallParam param = {
        .rax = __NR_recvmmsg,
        .rdi = sockfd,
        .rsi = (uint64_t)msgvec,
        .rdx = vlen,
        .r10 = flags,
        .r8 = (uint64_t)timeout,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fanotify_init(unsigned int flags, unsigned int event_f_flags)
{
    struct HypercallParam param = {
        .rax = __NR_fanotify_init,
        .rdi = flags,
        .rsi = event_f_flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int fd, const char *pathname)
{
    struct HypercallParam param = {
        .rax = __NR_fanotify_mark,
        .rdi = fanotify_fd,
        .rsi = flags,
        .rdx = mask,
        .r10 = fd,
        .r8 = (uint64_t)pathname,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_prlimit64(pid_t pid, int resource, const struct rlimit *new_limit,
                 struct rlimit *old_limit)
{
    struct HypercallParam param = {
        .rax = __NR_prlimit64,
        .rdi = pid,
        .rsi = resource,
        .rdx = (uint64_t)new_limit,
        .r10 = (uint64_t)old_limit,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags)
{
    struct HypercallParam param = {
        .rax = __NR_name_to_handle_at,
        .rdi = dirfd,
        .rsi = (uint64_t)pathname,
        .rdx = (uint64_t)handle,
        .r10 = (uint64_t)mount_id,
        .r8 = flags,
    };
    return hypercall(&param);
}

int hp_open_by_handle_at(int mount_fd, struct file_handle *handle,
                         int flags)
{
    struct HypercallParam param = {
        .rax = __NR_open_by_handle_at,
        .rdi = mount_fd,
        .rsi = (uint64_t)handle,
        .rdx = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_clock_adjtime(clockid_t which_clock, struct timex *tx)
{
    struct HypercallParam param = {
        .rax = __NR_clock_adjtime,
        .rdi = which_clock,
        .rsi = (uint64_t)tx,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_syncfs(int fd)
{
    struct HypercallParam param = {
        .rax = __NR_syncfs,
        .rdi = fd,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_renameat2(int olddfd, const char *oldname, int newdfd,
                 const char *newname, unsigned int flags)
{
    struct HypercallParam param = {
        .rax = __NR_renameat2,
        .rdi = olddfd,
        .rsi = (uint64_t)oldname,
        .rdx = newdfd,
        .r10 = (uint64_t)newname,
        .r8 = flags,
    };
    int ret = hypercall(&param);
    return ret;
}

int hp_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    struct HypercallParam param = {
        .rax = __NR_bpf,
        .rdi = cmd,
        .rsi = (uint64_t)attr,
        .rdx = size,
    };
    int ret = hypercall(&param);
    return ret;
}