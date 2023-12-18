#ifdef USE_GLIBC
#include <asm/unistd_64.h>
#else
#include <sys/syscall.h>
#endif
.include "syscall_vmpl.h"
.data
.globl __dune_vsyscall_page
.balign 4096, 0xcc
.type __dune_vsyscall_page, @object
__dune_vsyscall_page:

	/* handle gettimeofday() */
	mov $__NR_gettimeofday, %rax
	VMPL_SYSCALL
	ret

	/* handle time() */
	.balign 1024, 0xcc
	mov $__NR_time, %rax
	VMPL_SYSCALL
	ret

	/* handle getcpu() */
	.balign 1024, 0xcc
	mov $__NR_getcpu, %rax
	VMPL_SYSCALL
	ret

	.balign 4096, 0xcc
	.size __dune_vsyscall_page, 4096
