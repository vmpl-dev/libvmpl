/*
 * dune.S - assembly helper routines (e.g. system calls, interrupts, traps)
 */

#define __ASSEMBLY__
#include "svsm-vmpl.h"

#define USE_RDWRGSFS 0

#define MSR_FS_BASE	0xc0000100
#define GD_KT		0x10
#define GD_KD		0x18
#define GD_UD		0x28 | 0x03
#define GD_UT		0x30 | 0x03

/*
 * Trap Frame Format
 * NOTE: this reflects the layout of struct dune_tf
 */

/* arguments */
#define RDI	(0)
#define RSI	(8)
#define RDX	(16)
#define RCX	(24)
#define R8	(32)
#define R9	(40)

/* other registers */
#define R10	(48)
#define R11	(56)
#define RBX	(64)
#define RBP	(72)
#define R12	(80)
#define R13	(88)
#define R14	(96)
#define R15	(104)

#define REG_END	(112)

/* syscall num / return code */
#define RAX	(112)

/* exception frame */
#define ERR	(120)
#define RIP	(128)
#define CS	(136)
#define RFLAGS	(144)
#define RSP	(152)
#define SS	(160)

#define EF_START (128)
#define TF_END	(168)
#define TF_ALIGN (176)

/*
 * Supervisor Private Area Format
 */

#define TMP		(8)
#define KFS_BASE	(16)
#define UFS_BASE	(24)
#define IN_USERMODE	(32)
#define TRAP_STACK	(44)

.text

/*
 * macro to save destructable register state
 */
	.macro SAVE_REGS save_full=1, include_rax=1
	movq	%rdi, RDI(%rsp)
	movq	%rsi, RSI(%rsp)
	movq	%rdx, RDX(%rsp)
	movq	%r8, R8(%rsp)
	movq	%r9, R9(%rsp)

	.if \save_full
	movq	%r10, R10(%rsp)
	movq	%r11, R11(%rsp)
	movq	%rcx, RCX(%rsp)
	.endif

	.if \include_rax
	movq	%rax, RAX(%rsp)
	.endif
	.endm

/*
 * macro to save the rest of register state
 *
 * useful for operations that violate AMD64 calling conventions
 * by destroying callee restored state
 */
	.macro SAVE_REST
	movq	%rbx, RBX(%rsp)
	movq	%rbp, RBP(%rsp)
	movq	%r12, R12(%rsp)
	movq	%r13, R13(%rsp)
	movq	%r14, R14(%rsp)
	movq	%r15, R15(%rsp)
	.endm

/*
 * macro to restore destructable register state
 */
	.macro RESTORE_REGS rstor_full=1, include_rax=1
	.if \include_rax
	movq	RAX(%rsp), %rax
	.endif

	.if \rstor_full
	movq	RCX(%rsp), %rcx
	movq	R11(%rsp), %r11
	movq	R10(%rsp), %r10
	.endif

	movq	R9(%rsp), %r9
	movq	R8(%rsp), %r8
	movq	RDX(%rsp), %rdx
	movq	RSI(%rsp), %rsi
	movq	RDI(%rsp), %rdi
	.endm

/*
 * macro to restore the rest of register state
 *
 * useful for operations that violate AMD64 calling conventions
 * by destroying callee restored state
 */
	.macro RESTORE_REST
	movq	R15(%rsp), %r15
	movq	R14(%rsp), %r14
	movq	R13(%rsp), %r13
	movq	R12(%rsp), %r12
	movq	RBP(%rsp), %rbp
	movq	RBX(%rsp), %rbx
	.endm

/*
 * macro to switch to G0 fs.base
 *
 * NOTE: clobbers %rax, %rdx, and %rcx
 */
	.macro SET_G0_FS_BASE
	movq	$0, %gs:IN_USERMODE					// set IN_USERMODE to 0 (see __dune_enter)
	movq	%gs:KFS_BASE, %rax					// load the kernel FS.base address into %rax (see __dune_enter)
	movq	%gs:UFS_BASE, %rdx					// load the user FS.base address into %rdx (see __dune_enter)
	cmp	%rax, %rdx								// compare the kernel and user FS.base addresses (see __dune_enter)
	je	1f										// if they are equal, jump to 1 (see __dune_enter)
#if USE_RDWRGSFS
	wrfsbase %rax								// set FS.base to the kernel FS.base address (see __dune_enter)
#else
	movq	%rax, %rdx							// move the kernel FS.base address into %rdx (see __dune_enter)
	shrq	$32, %rdx							// shift the kernel FS.base address right by 32 bits (see __dune_enter)
	movl	$MSR_FS_BASE, %ecx					// load the FS.base MSR number into %ecx (see __dune_enter)
	wrmsr										// write the kernel FS.base address to the FS.base MSR (see __dune_enter)
#endif /* USE_RDWRGSFS */
1:
	.endm

/*
 * macro to switch to G3 fs.base
 *
 * NOTE: clobbers %rax, %rdx, and %rcx
 */
	.macro SET_G3_FS_BASE
	movq	$1, %gs:IN_USERMODE					// set IN_USERMODE to 1 (see __dune_enter)
	movq	%gs:UFS_BASE, %rax					// load the user FS.base address into %rax (see __dune_enter)
	movq	%gs:KFS_BASE, %rdx					// load the kernel FS.base address into %rdx (see __dune_enter)
	cmp	%rax, %rdx								// compare the kernel and user FS.base addresses (see __dune_enter)
	je	1f										// if they are equal, jump to 1 (see __dune_enter)
#if USE_RDWRGSFS
	wrfsbase %rax								// set FS.base to the user FS.base address (see __dune_enter)
#else
	movq	%rax, %rdx							// move the user FS.base address into %rdx (see __dune_enter)
	shrq	$32, %rdx							// shift the user FS.base address right by 32 bits (see __dune_enter)
	movl	$MSR_FS_BASE, %ecx					// load the FS.base MSR number into %ecx (see __dune_enter)
	wrmsr										// write the user FS.base address to the FS.base MSR (see __dune_enter)
#endif /* USE_RDWRGSFS */
1:
	.endm

.globl __dune_enter
__dune_enter:
	pushfq
	subq	$REG_END, %rsp				// reserve space for register state
	SAVE_REGS 1, 0						// save registers in stack frame (except RAX)
	SAVE_REST							// save the rest of the registers in stack frame (RBX, RBP, R12-R15)
	movq	%rsp, DUNE_CFG_RSP(%rsi)	// save RSP in config struct for later use in __dune_exit handler
	movq	%rsi, %rdx					// config
	movq	$IOCTL_DUNE_ENTER, %rsi		// ioctl number
	movq	$16, %rax /* __NR_ioctl */
	syscall

	cmpq	$0, %rax					// check return value
	jnz __dune_ret_fail					// if not 0, return to caller with error code in RAX (see __dune_ret_fail)

	movq	%rdi, %r12					// save RDI in %r12 for later use in __dune_exit handler
	movq	%rdx, %r13					// save config in %r13 for later use in __dune_exit handler

__dune_retry:
	/* Dune mode was terminated, call on_dune_exit handler function */
	movq	%r13, %rdi
	/* Update RSP to point to the top of the stack as seen from inside Dune
	 * mode. */
	movq	DUNE_CFG_RSP(%rdi), %rsp
	/* Go past the red zone mandated by the System V x86-64 ABI. */
	subq	$128, %rsp
	call	on_dune_exit
	int3 /* sentinel: on_dune_exit should not return */
__dune_reenter:
	movq	%r12, %rdi					// restore RDI from %r12 (saved in __dune_enter)
	movq	%r13, %rdx					// restore config from %r13 (saved in __dune_enter)
	movq	$IOCTL_DUNE_ENTER, %rsi		// ioctl number
	movq	$16, %rax /* __NR_ioctl */
	syscall
	cmpq	$0, %rax					// check return value (should be 0) and retry if not 0 (see __dune_retry)
	jz	__dune_retry					// if not 0, retry (see __dune_retry) (should never happen) (see __dune_ret_fail)
	movq	%rax, DUNE_CFG_STATUS(%r13)				// save return value in config struct for later use in __dune_exit handler
	movq	$DUNE_RET_NOENTER, DUNE_CFG_RET(%r13)	// save return value in config struct for later use in __dune_exit handler
	jmp	__dune_retry

/* __dune_ret is the location of the first instruction executed in Dune mode */
.globl	__dune_ret
__dune_ret:								// this is the entry point for the first time we enter Dune mode
	xorq %rax, %rax /* return 0 from __dune_enter */

__dune_ret_fail:						// return to caller with error code in RAX (see __dune_enter)
	RESTORE_REST						// restore the rest of the registers from stack frame (RBX, RBP, R12-R15)
	RESTORE_REGS 1, 0					// restore registers from stack frame (except RAX)
	addq	$REG_END, %rsp				// adjust the stack pointer to point to the exception frame
	popfq								// restore RFLAGS from stack frame
	retq								// return to the caller

.globl __dune_go_linux
__dune_go_linux:
	movq DUNE_CFG_RCX(%rdi), %rcx		// restore RCX from config struct
	movq DUNE_CFG_RBX(%rdi), %rbx		// restore RBX from config struct
	movq DUNE_CFG_RDX(%rdi), %rdx		// restore RDX from config struct
	movq DUNE_CFG_RBP(%rdi), %rbp		// restore RBP from config struct
	movq DUNE_CFG_RSI(%rdi), %rsi		// restore RSI from config struct
	movq DUNE_CFG_R8 (%rdi), %r8		// restore R8 from config struct
	movq DUNE_CFG_R9 (%rdi), %r9		// restore R9 from config struct
	movq DUNE_CFG_R10(%rdi), %r10		// restore R10 from config struct
	movq DUNE_CFG_R11(%rdi), %r11		// restore R11 from config struct
	movq DUNE_CFG_R12(%rdi), %r12		// restore R12 from config struct
	movq DUNE_CFG_R13(%rdi), %r13		// restore R13 from config struct
	movq DUNE_CFG_R14(%rdi), %r14		// restore R14 from config struct
	movq DUNE_CFG_R15(%rdi), %r15		// restore R15 from config struct
	mov %ss, %rax						// restore SS from config struct
	push %rax							// push SS onto the stack
	pushq DUNE_CFG_RSP(%rdi)			// push RSP onto the stack
	pushq DUNE_CFG_RFLAGS(%rdi)			// push RFLAGS onto the stack
	mov %cs, %rax						// restore CS from config struct
	push %rax							// push CS onto the stack
	pushq DUNE_CFG_RIP(%rdi)			// push RIP onto the stack
	pushq DUNE_CFG_RFLAGS(%rdi)			// push RFLAGS onto the stack
	movq DUNE_CFG_RAX(%rdi), %rax		// restore RAX from config struct
	movq DUNE_CFG_RDI(%rdi), %rdi		// restore RDI from config struct
	/* We are restoring the flags here, so that RFLAGS.TF is set when IRETQ is
	 * executed, so that an INT 1 will be raised _before_ executing the
	 * instruction at CS:RIP we are jumping to. */
	popf								// restore RFLAGS from stack frame
	iretq								// return to the caller (see __dune_go_linux)

.globl __dune_go_dune
__dune_go_dune:							// this is the entry point for the first time we enter Dune mode
	movq	%rdi, %r12					// save RDI in %r12 for later use in __dune_exit handler
	movq	%rsi, %r13					// save config in %r13 for later use in __dune_exit handler
	jmp	__dune_reenter					// jump to __dune_reenter (see __dune_reenter)

/*
 * System Call ABI
 * ---------------
 *
 * User Parameters:
 * %rsp - stack pointer
 * %rcx - instruction pointer
 * %r11 - eflags
 * %rax - system call number
 *
 * Arguments:
 * %rdi - arg0, %rsi - arg1, %rdx - arg2
 * %r10 - arg3, %r8 - arg4, %r9 - arg5
 *
 * Return code goes in %rax
 *
 * XXX: don't do relative jumps - watch out code is memcpy
 */
.globl __dune_syscall
__dune_syscall:
	/* handle system calls from G0 */
	testq $1, %gs:IN_USERMODE			// check if we are in G0 (see __dune_syscall)
	jnz 1f								// if not, jump to 1 (see __dune_syscall)
	pushq	%r11						// save RFLAGS on the stack (see __dune_syscall)
	popfq								// restore RFLAGS from stack frame (see __dune_syscall)
	vmcall								// call the VMM (see __dune_syscall)
	jmp	*%rcx							// jump to the return address (see __dune_syscall)

1:
	/* first switch to the kernel stack */
	movq	%rsp, %gs:TMP 				// save the user stack pointer in the TSS (see dune_jump_to_user)
	movq	%gs:TRAP_STACK, %rsp 		// switch to the kernel stack (see dune_jump_to_user)

	/* now push the trap frame onto the stack */
	subq	$TF_END, %rsp 				// reserve space for trap frame (see dune_jump_to_user)
	movq	%rcx, RIP(%rsp) 			// save RIP in trap frame (see dune_jump_to_user)
	movq	%r11, RFLAGS(%rsp) 			// save RFLAGS in trap frame (see dune_jump_to_user)
	movq	%r10, RCX(%rsp) /* fixup to standard 64-bit calling ABI */
	SAVE_REGS 0, 1 						// save registers in trap frame (except RAX) (see dune_jump_to_user)
	movq	%gs:TMP, %rax				// restore the user stack pointer from the TSS (see dune_jump_to_user)
	movq	%rax, RSP(%rsp)				// save RSP in trap frame (see dune_jump_to_user)

	/* then restore the CPL0 FS base address */
	SET_G0_FS_BASE						// switch to G0 (see dune_jump_to_user)

	/* then finally re-enable interrupts and jump to the handler */
	sti									// re-enable interrupts (see dune_jump_to_user) (see dune_syscall_handler)
	movq	%rsp, %rdi /* argument 0 */ // save the trap frame pointer in %rdi (see dune_syscall_handler)
	lea	dune_syscall_handler, %rax		// load the address of the syscall handler into %rax (see dune_jump_to_user)
	call	*%rax						// call the syscall handler (see dune_jump_to_user) (see dune_syscall_handler)

	/* next restore the CPL3 FS base address */
	SET_G3_FS_BASE						// switch to G3 (see dune_jump_to_user) (see dune_syscall_handler)

	/* then pop the trap frame off the stack */
	RESTORE_REGS 0, 1					// restore registers from trap frame (except RAX) (see dune_jump_to_user)
	movq	RCX(%rsp), %r10				// restore RCX from trap frame (see dune_jump_to_user) (see dune_syscall_handler)
	movq	RFLAGS(%rsp), %r11			// restore RFLAGS from trap frame (see dune_jump_to_user) (see dune_syscall_handler)
	movq	RIP(%rsp), %rcx				// restore RIP from trap frame (see dune_jump_to_user) (see dune_syscall_handler)

	/* switch to the user stack and return to ring 3 */
	movq	RSP(%rsp), %rsp				// restore RSP from trap frame (see dune_jump_to_user) (see dune_syscall_handler)
	sysretq								// return to ring 3 (see dune_jump_to_user) (see dune_syscall_handler)

.globl __dune_syscall_end
__dune_syscall_end:
	nop									// XXX: don't do relative jumps - watch out code is memcpy

.globl dune_pop_trap_frame
dune_pop_trap_frame:
	movq	%rdi, %rsp /* might actually not be a stack!!! */

	/* load the full register state */
	RESTORE_REGS						// restore registers from trap frame (except RAX) (see dune_jump_to_user) (see dune_syscall_handler)
	RESTORE_REST						// restore the rest of the registers from trap frame (RBX, RBP, R12-R15) (see dune_jump_to_user) (see dune_syscall_handler)

	/* jump to the frame */
	addq	$EF_START, %rsp				// adjust the stack pointer to point to the exception frame (see dune_jump_to_user) (see dune_syscall_handler)
	iretq								// return to ring 3 (see dune_jump_to_user) (see dune_syscall_handler)

.globl dune_jump_to_user
dune_jump_to_user:
	subq	$TF_ALIGN, %rsp				// reserve space for trap frame (see dune_syscall_handler)

	/* save the full register state */
	SAVE_REGS							// save registers in trap frame (except RAX) (see dune_syscall_handler)
	SAVE_REST							// save the rest of the registers in trap frame (RBX, RBP, R12-R15) (see dune_syscall_handler)
	pushfq								// save RFLAGS in trap frame (see dune_syscall_handler)
	popq	RFLAGS(%rsp)				// save RFLAGS in trap frame (see dune_syscall_handler)

	/* save the stack pointer */
	movq	%rsp, %gs:TRAP_STACK		// save the stack pointer in the TSS (see dune_syscall_handler)

	/* set the CPL 3 FS.base */
	SET_G3_FS_BASE						// switch to G3 (see dune_syscall_handler) (see dune_jump_to_user)

	/* jump into G3 */
	movq	$GD_UT, CS(%rdi)			// set CS to CPL 3 (see dune_syscall_handler) (see dune_jump_to_user)
	movq	$GD_UD, SS(%rdi)			// set SS to CPL 3 (see dune_syscall_handler) (see dune_jump_to_user)
	jmp	dune_pop_trap_frame

.globl dune_ret_from_user
dune_ret_from_user:
	/* restore the G0 stack */
	movq	%rdi, %rsi					// save the return code in %rsi (see dune_ret_from_user) (see dune_ret_from_user_finish)
	movq	%gs:TRAP_STACK, %rdi		// restore the stack pointer from the TSS (see dune_ret_from_user) (see dune_ret_from_user_finish)

	/* return code */
	movq	%rsi, RAX(%rdi)				// save the return code in the trap frame (see dune_ret_from_user) (see dune_ret_from_user_finish)

	/* fill in remaining exception frame data */
	lea	dune_ret_from_user_finish, %rax		// load the address of the return from user handler into %rax (see dune_ret_from_user) (see dune_ret_from_user_finish)
	movq	%rax, RIP(%rdi)					// save RIP in trap frame (see dune_ret_from_user) (see dune_ret_from_user_finish)
	movq	$GD_KT, CS(%rdi)				// set CS to CPL 0 (see dune_ret_from_user) (see dune_ret_from_user_finish)
	movq	$GD_KD, SS(%rdi) 				// set SS to CPL 0 (see dune_ret_from_user) (see dune_ret_from_user_finish)
	movq	%rdi, RSP(%rdi)					// save RSP in trap frame (see dune_ret_from_user) (see dune_ret_from_user_finish)

	/* return to the caller */
	jmp	dune_pop_trap_frame

dune_ret_from_user_finish:
	addq	$TF_ALIGN, %rsp					// adjust the stack pointer to point to the exception frame (see dune_ret_from_user) (see dune_ret_from_user_finish)
	ret

.globl __dune_intr
.align 16
__dune_intr:
	i = 0									// initialize the interrupt number to 0 (see __dune_intr)
	.rept 256								// loop over all possible interrupt numbers (see __dune_intr)
	.align 16								// align the interrupt handler (see __dune_intr)
	.if i <> 8 && (i <= 9 || i >= 15) && i <> 17			// skip reserved interrupts (see __dune_intr)
		pushq	%rax /* placeholder for no error code */	// push a placeholder for the error code (see __dune_intr)
	.endif
	pushq	%rax /* save %rax */			// save %rax (see __dune_intr)
	mov $i, %rax							// move the interrupt number into %rax (see __dune_intr)
	jmp __dune_intr_with_num				// jump to the interrupt handler (see __dune_intr)
	i = i + 1								// increment the interrupt number (see __dune_intr)
	.endr

__dune_intr_with_num:
	/* save all registers */
	subq	$REG_END, %rsp					// reserve space for register state (see __dune_intr)
	SAVE_REGS 1, 0 /* %rax already is pushed */				// save registers in stack frame (except RAX) (see __dune_intr)
	SAVE_REST								// save the rest of the registers in stack frame (RBX, RBP, R12-R15) (see __dune_intr)
	movq	%rax, %rdi						// save the interrupt number in %rdi (see __dune_intr)

	/* then restore the CPL0 FS base address */
	testq	$3, CS(%rsp)					// check if we are in CPL 0 (see __dune_intr)
	jz	__dune_intr_handler					// if not, jump to the handler (see __dune_intr)
	SET_G0_FS_BASE							// switch to G0 (see __dune_intr)

__dune_intr_handler:
	/* setup arguments and call the handler */
	movq	%rsp, %rsi						// save the stack pointer in %rsi (see __dune_intr)
	call	dune_trap_handler				// call the trap handler (see __dune_intr)

	/* next restore the CPL3 FS base address */
	testq	$3, CS(%rsp)					// check if we are in CPL 0 (see __dune_intr)
	jz	__dune_intr_done					// if not, jump to the handler (see __dune_intr)
	SET_G3_FS_BASE							// switch to G3 (see __dune_intr)

__dune_intr_done:
	/* load all registers */
	RESTORE_REST							// restore the rest of the registers from stack frame (RBX, RBP, R12-R15) (see __dune_intr)
	RESTORE_REGS							// restore registers from stack frame (except RAX) (see __dune_intr)

	/* jump to the frame */
	addq	$EF_START, %rsp					// adjust the stack pointer to point to the exception frame (see __dune_intr)
	iretq									// return to the caller (see __dune_intr)
