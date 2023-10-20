#ifndef HYPERCALL_H
#define HYPERCALL_H
#define _GNU_SOURCE /* See feature_test_macros(7) */
#define __USE_GNU

#include <stdint.h>
#include <syscall.h>
#include <poll.h>
#include <time.h>
#include <sys/capability.h>
#include <sys/dir.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/fcntl.h>
#include <sys/fsuid.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/poll.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
// #include <sys/syslog.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
// #include <off_t.h>
// #include <sys/capability.h>
#include <linux/aio_abi.h>
#include <linux/futex.h>
#include <linux/hw_breakpoint.h>
#include <linux/kexec.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/sysctl.h>
#include <linux/fs.h>
#include <linux/openat2.h>
#include <asm/ldt.h>
#include <aio.h>
#include <dirent.h>
#include <fcntl.h>
#include <features.h>
#include <mqueue.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <utime.h>
#include <keyutils.h>
#include <bpf/bpf.h>
// #include <sysctl.h>

// Hypercall functions
struct HypercallParam
{
    uint64_t rax;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    // Add more parameters as needed
};

uint64_t hypercall(struct HypercallParam *param);
// Add more hypercall functions as needed
ssize_t hp_read(int fd, void *buf, size_t count);
ssize_t hp_write(int fd, const void *buf, size_t count);
int hp_open(const char *pathname, int flags, mode_t mode);
int hp_close(int fd);
int hp_stat(const char *pathname, struct stat *statbuf);
int hp_fstat(int fd, struct stat *statbuf);
int hp_lstat(const char *pathname, struct stat *statbuf);
int hp_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int hp_lseek(int fildes, uint32_t offset, int whence);
void *hp_mmap(void *addr, size_t length, int prot, int flags,
              int fd, off_t offset);
int hp_mprotect(void *addr, size_t len, int prot);
int hp_munmap(void *addr, size_t length);
int hp_brk(void *addr);
int hp_rt_sigaction(int signum, const struct sigaction *act,
                    struct sigaction *oldact);
int hp_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
int hp_rt_sigreturn(void);
int hp_ioctl(int fd, unsigned long request, ...);
int hp_pread64(int fd, void *buf, size_t count, off_t offset);
int hp_pwrite64(int fd, const void *buf, size_t count, off_t offset);
int hp_readv(int fd, const struct iovec *iov, int iovcnt);
int hp_writev(int fd, const struct iovec *iov, int iovcnt);
int hp_access(const char *pathname, int mode);
int hp_pipe(int pipefd[2]);
int hp_select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout);
int hp_sched_yield(void);
int hp_mremap(void *old_address, size_t old_size, size_t new_size,
              int flags, void *new_address);
int hp_msync(void *addr, size_t length, int flags);
int hp_mincore(void *addr, size_t length, unsigned char *vec);
int hp_madvise(void *addr, size_t length, int advice);
int hp_shmget(key_t key, size_t size, int shmflg);
void *hp_shmat(int shmid, const void *shmaddr, int shmflg);
int hp_shmctl(int shmid, int cmd, struct shmid_ds *buf);
int hp_dup(int oldfd);
int hp_dup2(int oldfd, int newfd);
int hp_pause(void);
int hp_nanosleep(const struct timespec *req, struct timespec *rem);
int hp_getitimer(int which, struct itimerval *curr_value);
unsigned int hp_alarm(unsigned int seconds);
int hp_setitimer(int which, const struct itimerval *new_value,
                 struct itimerval *old_value);
pid_t hp_getpid(void);
ssize_t hp_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
int hp_socket(int domain, int type, int protocol);
int hp_connect(int sockfd, const struct sockaddr *addr,
               socklen_t addrlen);
int hp_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t hp_sendto(int sockfd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t hp_recvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t hp_sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t hp_recvmsg(int sockfd, struct msghdr *msg, int flags);
int hp_shutdown(int sockfd, int how);
int hp_bind(int sockfd, const struct sockaddr *addr,
            socklen_t addrlen);
int hp_listen(int sockfd, int backlog);
int hp_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int hp_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int hp_socketpair(int domain, int type, int protocol, int sv[2]);
int hp_getsockopt(int sockfd, int level, int optname,
                  void *optval, socklen_t *optlen);
int hp_setsockopt(int sockfd, int level, int optname,
                  const void *optval, socklen_t optlen);
pid_t hp_gettid(void);
pid_t hp_fork(void);
pid_t hp_vfork(void);
void hp_exit(int status);
int hp_execve(const char *path, char *const argv[], char *const envp[]);
int hp_wait4(pid_t pid, int *status, int options, struct rusage *rusage);
int hp_kill(pid_t pid, int sig);
int hp_uname(struct utsname *buf);
int hp_semget(key_t key, int nsems, int semflg);
int hp_semop(int semid, struct sembuf *sops, size_t nsops);
int hp_semctl(int semid, int semnum, int cmd, ...);
int hp_shmdt(const void *shmaddr);
int hp_msgget(key_t key, int msgflg);
int hp_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
ssize_t hp_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp,
                  int msgflg);
int hp_msgctl(int msqid, int cmd, struct msqid_ds *buf);
int hp_fcntl(int fd, int cmd, ... /* arg */ );
int hp_flock(int fd, int operation);
int hp_fsync(int fd);
int hp_fdatasync(int fd);
int hp_truncate(const char *path, off_t length);
int hp_ftruncate(int fd, off_t length);
long hp_getdents(unsigned int fd, void *dirp,
                 unsigned int count);
char *hp_getcwd(char *buf, size_t size);
int hp_chdir(const char *path);
int hp_fchdir(int fd);
int hp_rename(const char *oldpath, const char *newpath);
int hp_mkdir(const char *pathname, mode_t mode);
int hp_rmdir(const char *pathname);
int hp_creat(const char *pathname, mode_t mode);
int hp_link(const char *oldpath, const char *newpath);
int hp_unlink(const char *pathname);
int hp_symlink(const char *target, const char *linkpath);
ssize_t hp_readlink(const char *pathname, char *buf, size_t bufsiz);
int hp_chmod(const char *pathname, mode_t mode);
int hp_fchmod(int fd, mode_t mode);
int hp_chown(const char *pathname, uid_t owner, gid_t group);
int hp_fchown(int fd, uid_t owner, gid_t group);
int hp_lchown(const char *pathname, uid_t owner, gid_t group);
__mode_t hp_umask(mode_t mask);
int hp_gettimeofday(struct timeval *tv, struct timezone *tz);
int hp_getrlimit(int resource, struct rlimit *rlim);
int hp_getrusage(int who, struct rusage *usage);
int hp_sysinfo(struct sysinfo *info);
clock_t hp_times(struct tms *buf);
int hp_ptrace(long request, pid_t pid, void *addr, void *data);
__uid_t hp_getuid(void);
void hp_syslog(int type, char *bufp, int len);
__gid_t hp_getgid(void);
int hp_setuid(uid_t uid);
int hp_setgid(gid_t gid);
__uid_t hp_geteuid(void);
__gid_t hp_getegid(void);
int hp_setpgid(pid_t pid, pid_t pgid);
pid_t hp_getppid(void);
pid_t hp_getpgrp(void);
pid_t hp_setsid(void);
__pid_t hp_getpgid(pid_t pid);
int hp_setreuid(uid_t ruid, uid_t euid);
int hp_setregid(gid_t rgid, gid_t egid);
int hp_getgroups(int size, gid_t list[]);
int hp_setgroups(size_t size, const gid_t *list);
int hp_setresuid(uid_t ruid, uid_t euid, uid_t suid);
int hp_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
int hp_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
int hp_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
pid_t hp_getpgid(pid_t pid);
int hp_setfsuid(uid_t uid);
int hp_setfsgid(gid_t gid);
pid_t hp_getsid(pid_t pid);
int hp_capget(cap_user_header_t hdrp, cap_user_data_t datap);
int hp_capset(cap_user_header_t hdrp, const cap_user_data_t datap);
int hp_rt_sigpending(sigset_t *set, size_t sigsetsize);
int hp_rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
                       const struct timespec *uts, size_t sigsetsize);
int hp_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *uinfo);
int hp_rt_sigsuspend(const sigset_t *unewset, size_t sigsetsize);
int hp_sigaltstack(const stack_t *uss, stack_t *uoss);
int hp_utime(const char *filename, const struct utimbuf *times);
int hp_mknod(const char *pathname, mode_t mode, dev_t dev);
int hp_uselib(const char *library);
int hp_statfs(const char *path, struct statfs *buf);
int hp_fstatfs(int fd, struct statfs *buf);
int hp_sysfs(int option, unsigned long arg1, unsigned long arg2);
int hp_getpriority(__priority_which_t __which, id_t __who);
int hp_setpriority(__priority_which_t __which, id_t __who, int __prio);
int hp_sched_setparam(pid_t pid, const struct sched_param *param);
int hp_sched_getparam(pid_t pid, struct sched_param *param);
int hp_sched_setscheduler(pid_t pid, int policy,
                          const struct sched_param *param);
int hp_sched_getscheduler(pid_t pid);
int hp_sched_get_priority_max(int policy);
int hp_sched_get_priority_min(int policy);
int hp_sched_rr_get_interval(pid_t pid, struct timespec *tp);
int hp_mlock(const void *addr, size_t len);
int hp_munlock(const void *addr, size_t len);
int hp_mlockall(int flags);
int hp_munlockall(void);
int hp_vhangup(void);
int hp_modify_ldt(int func, void *ptr, unsigned long bytecount);
int hp_pivot_root(const char *new_root, const char *put_old);
int hp__sysctl(struct __sysctl_args *args);
// int hp_prctl(int option, unsigned long arg2, unsigned long arg3,
//  unsigned long arg4, unsigned long arg5);
int hp_arch_prctl(int code, unsigned long addr);
int hp_adjtimex(struct timex *buf);
int hp_setrlimit(int resource, const struct rlimit *rlim);
int hp_chroot(const char *path);
void hp_sync(void);
int hp_acct(const char *filename);
int hp_settimeofday(const struct timeval *tv, const struct timezone *tz);
int hp_mount(const char *source, const char *target,
             const char *filesystemtype, unsigned long mountflags,
             const void *data);
int hp_umount2(const char *target, int flags);
int hp_swapon(const char *path, int swapflags);
int hp_swapoff(const char *path);
void hp_reboot(int magic1, int magic2, unsigned int cmd, void *arg);
int hp_sethostname(const char *name, size_t len);
int hp_setdomainname(const char *name, size_t len);
int hp_iopl(int level);
int hp_ioperm(unsigned long from, unsigned long num, int turn_on);
int hp_create_module(const char *name, size_t size);
int hp_init_module(void *module_image, unsigned long len,
                   const char *param_values);
int hp_delete_module(const char *name, int flags);
int hp_query_module(const char *name,
                    int which, void *buf, size_t bufsize, size_t *ret);
int hp_quotactl(int cmd, const char *special, int id, caddr_t addr);
int hp_gettid(void);
int hp_setxattr(const char *path, const char *name, const void *value,
                size_t size, int flags);
int hp_lsetxattr(const char *path, const char *name, const void *value,
                 size_t size, int flags);
int hp_fsetxattr(int fd, const char *name, const void *value,
                 size_t size, int flags);
ssize_t hp_getxattr(const char *path, const char *name, void *value,
                    size_t size);
ssize_t hp_lgetxattr(const char *path, const char *name, void *value,
                     size_t size);
ssize_t hp_fgetxattr(int fd, const char *name, void *value, size_t size);
ssize_t hp_listxattr(const char *path, char *list, size_t size);
ssize_t hp_llistxattr(const char *path, char *list, size_t size);
ssize_t hp_flistxattr(int fd, char *list, size_t size);
int hp_removexattr(const char *path, const char *name);
int hp_lremovexattr(const char *path, const char *name);
int hp_fremovexattr(int fd, const char *name);
int hp_tkill(int tid, int sig);
time_t hp_time(time_t *tloc);
int hp_futex(int *uaddr, int op, int val, const struct timespec *timeout,
             int *uaddr2, int val3);
int hp_sched_setaffinity(pid_t pid, size_t cpusetsize,
                         const cpu_set_t *mask);
int hp_sched_getaffinity(pid_t pid, size_t cpusetsize,
                         cpu_set_t *mask);
int hp_set_thread_area(struct user_desc *u_info);
int hp_io_setup(unsigned nr_events, aio_context_t *ctxp);
int hp_io_destroy(aio_context_t ctx);
int hp_io_getevents(aio_context_t ctx_id, long min_nr, long nr,
                    struct io_event *events, struct timespec *timeout);
int hp_io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
int hp_io_cancel(aio_context_t ctx_id, struct iocb *iocb,
                 struct io_event *result);
int hp_get_thread_area(struct user_desc *u_info);
int hp_lookup_dcookie(unsigned long cookie, char *buf, size_t len);
int hp_epoll_create(int size);
int hp_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int hp_epoll_wait(int epfd, struct epoll_event *events,
                  int maxevents, int timeout);
int hp_remap_file_pages(void *addr, size_t size, int prot,
                        ssize_t pgoff, int flags);
ssize_t hp_getdents64(int fd, void *dirp, size_t count);
int hp_set_tid_address(int *tidptr);
int hp_restart_syscall(void);
int hp_semtimedop(int semid, struct sembuf *sops, unsigned nsops,
                  const struct timespec *timeout);
int hp_fadvise64(int fd, loff_t offset, size_t len, int advice);
int hp_timer_create(clockid_t clockid, struct sigevent *sevp,
                    timer_t *timerid);
int hp_timer_settime(timer_t timerid, int flags,
                     const struct itimerspec *new_value,
                     struct itimerspec *old_value);
int hp_timer_gettime(timer_t timerid, struct itimerspec *curr_value);
int hp_timer_getoverrun(timer_t timerid);
int hp_timer_delete(timer_t timerid);
int hp_clock_settime(clockid_t clockid, const struct timespec *tp);
int hp_clock_gettime(clockid_t clockid, struct timespec *tp);
int hp_clock_getres(clockid_t clockid, struct timespec *res);
int hp_clock_nanosleep(clockid_t clockid, int flags,
                       const struct timespec *req,
                       struct timespec *rem);
int hp_exit_group(int status);
int hp_epoll_wait(int epfd, struct epoll_event *events,
                  int maxevents, int timeout);
int hp_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int hp_tgkill(int tgid, int tid, int sig);
int hp_utimes(const char *filename, const struct timeval times[2]);
int hp_mbind(void *addr, unsigned long len, int mode,
             unsigned long *nodemask, unsigned long maxnode,
             unsigned flags);
int hp_set_mempolicy(int mode, unsigned long *nodemask,
                     unsigned long maxnode);
int hp_get_mempolicy(int *policy, unsigned long *nodemask,
                     unsigned long maxnode, void *addr,
                     unsigned long flags);
int hp_mq_open(const char *name, int oflag, mode_t mode,
               struct mq_attr *attr);
int hp_mq_unlink(const char *name);

int hp_mq_timedsend(mqd_t mqdes, const char *msg_ptr,
                    size_t msg_len, unsigned int msg_prio,
                    const struct timespec *abs_timeout);
ssize_t hp_mq_timedreceive(mqd_t mqdes, char *msg_ptr,
                           size_t msg_len, unsigned int *msg_prio,
                           const struct timespec *abs_timeout);
int hp_mq_notify(mqd_t mqdes, const struct sigevent *sevp);
int hp_mq_getsetattr(mqd_t mqdes, const struct mq_attr *newattr,
                     struct mq_attr *oldattr);
int hp_kexec_load(unsigned long entry, unsigned long nr_segments,
                  struct kexec_segment *segments, unsigned long flags);
int hp_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options);
int hp_add_key(const char *_type, const char *_description,
               const void *_payload, size_t plen,
               key_serial_t destringid);
int hp_request_key(const char *_type, const char *_description,
                   const char *_callout_info, key_serial_t destringid);
int hp_keyctl(int cmd, ...);
int hp_ioprio_set(int which, int who, int ioprio);
int hp_ioprio_get(int which, int who);
int hp_inotify_init(void);
int hp_inotify_add_watch(int fd, const char *pathname, uint32_t mask);
int hp_inotify_rm_watch(int fd, int wd);
int hp_migrate_pages(int pid, unsigned long maxnode,
                     const unsigned long *old_nodes,
                     const unsigned long *new_nodes);
int hp_openat(int dirfd, const char *pathname, int flags, mode_t mode);
int hp_mkdirat(int dirfd, const char *pathname, mode_t mode);
int hp_mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
int hp_fchownat(int dirfd, const char *pathname, uid_t owner,
                gid_t group, int flags);
int hp_futimesat(int dirfd, const char *pathname,
                 const struct timeval times[2]);
int hp_newfstatat(int dirfd, const char *pathname,
                  struct stat *statbuf, int flags);
int hp_unlinkat(int dirfd, const char *pathname, int flags);
int hp_renameat(int olddirfd, const char *oldpath,
                int newdirfd, const char *newpath);
int hp_linkat(int olddirfd, const char *oldpath,
              int newdirfd, const char *newpath, int flags);
int hp_symlinkat(const char *oldpath, int newdirfd, const char *newpath);
ssize_t hp_readlinkat(int dirfd, const char *pathname,
                      char *buf, size_t bufsiz);
int hp_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
int hp_faccessat(int dirfd, const char *pathname, int mode, int flags);
int hp_pselect6(int nfds, fd_set *readfds, fd_set *writefds,
                fd_set *exceptfds, struct timespec *timeout,
                void *sigmask);
int hp_ppoll(struct pollfd *fds, nfds_t nfds,
             const struct timespec *tmo_p, const sigset_t *sigmask);
int hp_unshare(int flags);
long hp_set_robust_list(struct robust_list_head *head, size_t len);
long hp_get_robust_list(int pid, struct robust_list_head **head_ptr,
                       size_t *len_ptr);
int hp_splice(int fd_in, loff_t *off_in, int fd_out,
              loff_t *off_out, size_t len, unsigned int flags);
int hp_tee(int fdin, int fdout, size_t len, unsigned int flags);
int hp_sync_file_range(int fd, loff_t offset, loff_t nbytes,
                       unsigned int flags);
int hp_vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs,
                unsigned int flags);
int hp_move_pages(int pid, unsigned long count, void **pages,
                  const int *nodes, int *status, int flags);
int hp_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
int hp_epoll_pwait(int epfd, struct epoll_event *events,
                   int maxevents, int timeout, const sigset_t *sigmask);
int hp_signalfd(int fd, const sigset_t *mask);
int hp_timerfd_create(int clockid, int flags);
int hp_eventfd(unsigned int initval, int flags);
int hp_fallocate(int fd, int mode, off_t offset, off_t len);
int hp_timerfd_settime(int fd, int flags,
                       const struct itimerspec *new_value,
                       struct itimerspec *old_value);
int hp_timerfd_gettime(int fd, struct itimerspec *curr_value);
int hp_accept4(int sockfd, struct sockaddr *addr,
               socklen_t *addrlen, int flags);
int hp_signalfd4(int fd, const sigset_t *mask, int flags);
int hp_eventfd2(unsigned int initval, int flags);
int hp_epoll_create1(int flags);
int hp_dup3(int oldfd, int newfd, int flags);
int hp_pipe2(int pipefd[2], int flags);
int hp_inotify_init1(int flags);
ssize_t hp_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t hp_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
int hp_rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *uinfo);
int hp_perf_event_open(struct perf_event_attr *attr_uptr,
                       pid_t pid, int cpu, int group_fd,
                       unsigned long flags);
int hp_recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                int flags, struct timespec *timeout);
int hp_fanotify_init(unsigned int flags, unsigned int event_f_flags);
int hp_fanotify_mark(int fanotify_fd, unsigned int flags,
                     uint64_t mask, int dirfd, const char *pathname);
int hp_prlimit64(pid_t pid, int resource, const struct rlimit *new_limit,
                 struct rlimit *old_limit);
int hp_name_to_handle_at(int dirfd, const char *pathname,
                         struct file_handle *handle, int *mount_id,
                         int flags);
int hp_open_by_handle_at(int mount_fd, struct file_handle *handle,
                         int flags);
int hp_clock_adjtime(clockid_t clockid, struct timex *buf);
int hp_syncfs(int fd);
int hp_sendmmsg(int sockfd, struct mmsghdr *msgvec,
                unsigned int vlen, unsigned int flags);
int hp_setns(int fd, int nstype);
int hp_process_vm_readv(pid_t pid, const struct iovec *local_iov,
                        unsigned long liovcnt, const struct iovec *remote_iov,
                        unsigned long riovcnt, unsigned long flags);
int hp_process_vm_writev(pid_t pid, const struct iovec *local_iov,
                         unsigned long liovcnt, const struct iovec *remote_iov,
                         unsigned long riovcnt, unsigned long flags);
int hp_kcmp(pid_t pid1, pid_t pid2, int type,
            unsigned long idx1, unsigned long idx2);
int hp_finit_module(int fd, const char *uargs, int flags);
int hp_renameat2(int olddirfd, const char *oldpath,
                 int newdirfd, const char *newpath, unsigned int flags);
int hp_seccomp(unsigned int op, unsigned int flags,
               const char *uargs);
int hp_getrandom(void *buf, size_t buflen, unsigned int flags);
int hp_memfd_create(const char *uname_ptr, unsigned int flags);
int hp_kexec_file_load(int kernel_fd, int initrd_fd,
                       unsigned long cmdline_len, const char *cmdline_ptr,
                       unsigned long flags);
int hp_bpf(int cmd, union bpf_attr *attr, unsigned int size);
int hp_execveat(int dirfd, const char *pathname,
                char *const argv[], char *const envp[],
                int flags);
int hp_userfaultfd(int flags);
int hp_membarrier(int cmd, int flags);
int hp_mlock2(const void *addr, size_t len, int flags);
int hp_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                       loff_t *off_out, size_t len, unsigned int flags);
int hp_preadv2(int fd, const struct iovec *iov, int iovcnt,
               off_t offset, int flags);
int hp_pwritev2(int fd, const struct iovec *iov, int iovcnt,
                off_t offset, int flags);
int hp_pkey_mprotect(void *addr, size_t len, int prot, int pkey);
int hp_pkey_alloc(unsigned long flags, unsigned long init_val);
int hp_pkey_free(int pkey);
int hp_statx(int dirfd, const char *pathname, int flags,
             unsigned int mask, struct statx *statxbuf);
int hp_io_pgetevents(aio_context_t ctx_id, long min_nr, long nr,
                     struct io_event *events,
                     struct timespec *timeout,
                     const struct __aio_sigset *sig);
int hp_rseq(struct rseq *rseq, uint32_t rseq_len, int flags,
            uint32_t sig);
int hp_pidfd_send_signal(int pidfd, const siginfo_t *siginfo,
                         unsigned int flags);
int hp_io_uring_setup(unsigned entries, struct io_uring_params *p);
int hp_io_uring_enter(int fd, unsigned to_submit,
                      unsigned min_complete, unsigned flags,
                      sigset_t *sig);
int hp_io_uring_register(int fd, unsigned opcode, const void *arg,
                         unsigned nr_args);
int hp_open_tree(int dfd, const char *filename, unsigned flags);
int hp_move_mount(int from_dfd, const char *from_pathname,
                  int to_dfd, const char *to_pathname,
                  unsigned int flags);
int hp_fsopen(const char *fs_name, unsigned int flags);
int hp_fsconfig(int fs_fd, unsigned int cmd, const char *key,
                const void *value, int aux);
int hp_fsmount(int fs_fd, unsigned int flags, unsigned int ms_flags);
int hp_fspick(int dfd, const char *path, unsigned int flags);
int hp_pidfd_open(pid_t pid, unsigned int flags);
int hp_clone3(struct clone_args *uargs, size_t size);
int hp_openat2(int dfd, const char *filename,
               struct open_how *how, size_t size);
int hp_pidfd_getfd(int pidfd, int fd, unsigned int flags);
int hp_faccessat2(int dirfd, const char *pathname, int mode,
                  int flags);
int hp_process_madvise(int pid, const struct iovec *vec,
                       size_t vlen, int behavior);
int hp_epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                    const struct timespec *timeout,
                    const sigset_t *sigmask);
int hp_mount_setattr(int dfd, const char *path, unsigned int flags,
                     struct mount_attr *uattr, size_t usize);
int hp_memfd_secret(void *addr, size_t len, unsigned int flags);
int hp_process_mrelease(void *addr, size_t len);
int hp_userfaultfd_flags(unsigned long flags);
int hp_semget(key_t key, int nsems, int semflg);
int hp_semctl(int semid, int semnum, int cmd, ...);
int hp_shmget(key_t key, size_t size, int shmflg);
void *hp_shmat(int shmid, const void *shmaddr, int shmflg);
int hp_shmctl(int shmid, int cmd, struct shmid_ds *buf);
int hp_msgget(key_t key, int msgflg);
int hp_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
ssize_t hp_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp,
                  int msgflg);
int hp_msgctl(int msqid, int cmd, struct msqid_ds *buf);

#endif // HYPERCALL_H