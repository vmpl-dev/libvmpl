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
	mov    %cs,%ax
	test   $0x3,%al
	mov    $__NR_gettimeofday,%rdi
	jne    1f
	mov    $0xc0010130,%r8d
	mov    %r8d,%ecx
	rdmsr
	shl    $0x20,%rdx
	mov    %eax,%eax
	or     %rax,%rdx
	mov    $0x16,%eax
	mov    %rdx,%r9
	xor    %edx,%edx
	wrmsr
	mov    %rdi,%rax
	vmgexit
	mov    %rax,%rdi
	mov    %r8d,%ecx
	rdmsr
	mov    %rdx,%rsi
	mov    %eax,%eax
	mov    %r9,%rdx
	shl    $0x20,%rsi
	shr    $0x20,%rdx
	or     %rax,%rsi
	mov    %r9d,%eax
	wrmsr
	mov    %rsi,%rdx
	or     $0xffffffffffffffff,%rax
	and    $0xfff,%edx
	cmp    $0x17,%rdx
	cmovne %rax,%rdi
	shr    $0x20,%rsi
	cmove  %rdi,%rax
	ret
1:
	mov    %rdi,%rax
	syscall
	ret

	/* handle time() */
	.balign 1024, 0xcc
	mov    %cs,%ax
	test   $0x3,%al
	mov    $__NR_time,%rdi
	jne    2f
	mov    $0xc0010130,%r8d
	mov    %r8d,%ecx
	rdmsr
	shl    $0x20,%rdx
	mov    %eax,%eax
	or     %rax,%rdx
	mov    $0x16,%eax
	mov    %rdx,%r9
	xor    %edx,%edx
	wrmsr
	mov    %rdi,%rax
	vmgexit
	mov    %rax,%rdi
	mov    %r8d,%ecx
	rdmsr
	mov    %rdx,%rsi
	mov    %eax,%eax
	mov    %r9,%rdx
	shl    $0x20,%rsi
	shr    $0x20,%rdx
	or     %rax,%rsi
	mov    %r9d,%eax
	wrmsr
	mov    %rsi,%rdx
	or     $0xffffffffffffffff,%rax
	and    $0xfff,%edx
	cmp    $0x17,%rdx
	cmovne %rax,%rdi
	shr    $0x20,%rsi
	cmove  %rdi,%rax
	ret
2:
	mov    %rdi,%rax
	syscall
	ret

	/* handle getcpu() */
	.balign 1024, 0xcc
	mov    %cs,%ax
	test   $0x3,%al
	mov    $__NR_getcpu,%rdi
	jnz    3f
	mov    $0xc0010130,%r8d
	mov    %r8d,%ecx
	rdmsr
	shl    $0x20,%rdx
	mov    %eax,%eax
	or     %rax,%rdx
	mov    $0x16,%eax
	mov    %rdx,%r9
	xor    %edx,%edx
	wrmsr
	mov    %rdi,%rax
	vmgexit
	mov    %rax,%rdi
	mov    %r8d,%ecx
	rdmsr
	mov    %rdx,%rsi
	mov    %eax,%eax
	mov    %r9,%rdx
	shl    $0x20,%rsi
	shr    $0x20,%rdx
	or     %rax,%rsi
	mov    %r9d,%eax
	wrmsr
	mov    %rsi,%rdx
	or     $0xffffffffffffffff,%rax
	and    $0xfff,%edx
	cmp    $0x17,%rdx
	cmovne %rax,%rdi
	shr    $0x20,%rsi
	cmove  %rdi,%rax
	ret
3:
	mov    %rdi,%rax
	syscall
	ret

	.balign 4096, 0xcc
	.size __dune_vsyscall_page, 4096
