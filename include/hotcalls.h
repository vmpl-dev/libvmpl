#ifndef __HOTCALLS_H__
#define __HOTCALLS_H__

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

// Define the maximum number of system calls
#define MAX_SYSCALLS __NR_syscalls

// Define the hotcalls function type
typedef long (*hotcall_t)(long, ...);

// Define the exported hotcall functions
extern long exec_hotcall(long nr, ...);

#endif