#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <time.h>
#include <poll.h>
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