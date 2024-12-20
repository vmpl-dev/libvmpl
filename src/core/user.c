#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include "vmpl.h"
#include "log.h"

struct user_args {
	unsigned long arg1;
	unsigned long arg2;
	unsigned long arg3;
	unsigned long arg4;
	unsigned long arg5;
	unsigned long arg6;
};

/* Utility functions. */
static int dune_call_user(void *func, struct user_args *args)
{
	int ret;
	unsigned long sp;
	struct pt_regs *tf = malloc(sizeof(struct pt_regs));
	if (!tf)
		return -ENOMEM;

	asm ("movq %%rsp, %0" : "=r" (sp));
	sp = sp - 0x10008;
	tf->rip = (unsigned long) func;
	tf->rsp = sp;
	tf->eflags = 0x0;

	// Function arguments
	tf->rdi = args->arg1;
	tf->rsi = args->arg2;
	tf->rdx = args->arg3;
	tf->rcx = args->arg4;
	tf->r8 = args->arg5;
	tf->r9 = args->arg6;

	log_debug("entering user mode...");

	// Register syscall handler, default to passthrough
	dune_register_syscall_handler(&dune_passthrough_syscall);

	// Jump to user mode
	ret = dune_jump_to_user(tf);

	return ret;
}

int dune_call_user_func(void *func, ...)
{
	va_list ap;
	struct user_args args = {0};

	va_start(ap, func);
	args.arg1 = va_arg(ap, unsigned long);
	args.arg2 = va_arg(ap, unsigned long);
	args.arg3 = va_arg(ap, unsigned long);
	args.arg4 = va_arg(ap, unsigned long);
	args.arg5 = va_arg(ap, unsigned long);
	args.arg6 = va_arg(ap, unsigned long);
	va_end(ap);

	return dune_call_user(func, &args);
}

int dune_call_user_main(void *func, int argc, char **argv, char **envp)
{
	struct user_args args = {
		.arg1 = argc,
		.arg2 = (unsigned long) argv,
		.arg3 = (unsigned long) envp,
		.arg4 = 0,
		.arg5 = 0,
		.arg6 = 0,
	};

	return dune_call_user(func, &args);
}

int dune_call_user_thread(void *func, void *arg)
{
	struct user_args args = {
		.arg1 = (unsigned long) arg,
		.arg2 = 0,
		.arg3 = 0,
		.arg4 = 0,
		.arg5 = 0,
		.arg6 = 0,
	};

	return dune_call_user(func, &args);
}