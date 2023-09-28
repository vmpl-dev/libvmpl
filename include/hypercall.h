#ifndef HYPERCALL_H
#define HYPERCALL_H
#define _GNU_SOURCE

#include <stdint.h>
#include <syscall.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

// Hypercall functions
struct HypercallParam {
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
int hp_read(int fildes, uint64_t phy_addr, uint64_t nbyte);
int hp_write(int fildes, uint64_t phy_addr, uint64_t nbyte);
int hp_open(uint64_t paddr);
int hp_close(int fildes);
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
pid_t hp_getpid(void);
pid_t hp_gettid(void);
void hp_exit(void);

#endif // HYPERCALL_H