#ifdef USE_GLIBC
#include <asm/unistd_64.h>
#else
#include <bits/syscall.h>
#endif

.data
.globl __dune_vsyscall_page
.balign 4096, 0xcc
.type __dune_vsyscall_page, @object
__dune_vsyscall_page:

	/* handle gettimeofday() */
	mov %cs, %rax
	test $3, %rax
	mov $__NR_gettimeofday, %rax
	jnz 1f
	mov $1, %rsi
	call vc_run_vmpl
	ret
1:
	syscall
	ret

	/* handle time() */
	.balign 1024, 0xcc
	mov %cs, %rax
	test $3, %rax
	mov $__NR_time, %rax
	jnz 2f
	mov $1, %rsi
	call vc_run_vmpl
	ret
2:
	syscall
	ret

	/* handle getcpu() */
	.balign 1024, 0xcc
	mov %cs, %rax
	test $3, %rax
	mov $__NR_getcpu, %rax
	jnz 3f
	mov $1, %rsi
	call vc_run_vmpl
	ret
3:
	syscall
	ret

	.balign 4096, 0xcc
	.size __dune_vsyscall_page, 4096
