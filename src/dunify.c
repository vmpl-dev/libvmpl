/*
 * Hook main() using LD_PRELOAD to insert a call to dune_init_and_enter
 *
 * Compile using 'gcc dunify.c -o dunify.so -fPIC -shared -ldl'
 * Then run your program as 'LD_PRELOAD=$PWD/dunify.so ./a.out'
 *
 * Adapted from: https://gist.github.com/apsun/1e144bf7639b22ff0097171fa0f8c6b1
 */

#define _GNU_SOURCE
#include <execinfo.h>
#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "config.h"
#include "vc.h"
#include "vmpl.h"
#include "mm.h"
#include "log.h"
#include "dunify.h"

// environment variables
bool hotcalls_enabled = false;
bool vmpl_enabled = false;
bool run_in_vmpl = false;
bool run_in_vmpl_process = false;
bool run_in_vmpl_thread = false;
bool run_in_user_mode = false;

static void init_env()
{
	if (getenv("VMPL_ENABLED")) {
		vmpl_enabled = true;
		log_debug("vmpl enabled");
	}

	if (getenv("RUN_IN_VMPL")) {
		run_in_vmpl = true;
		log_debug("run in vmpl");
	}

	if (getenv("RUN_IN_VMPL_PROCESS")) {
		run_in_vmpl_process = true;
		log_debug("run in vmpl process");
	}

	if (getenv("RUN_IN_VMPL_THREAD")) {
		run_in_vmpl_thread = true;
		log_debug("run in vmpl thread");
	}

	if (getenv("RUN_IN_USER_MODE")) {
		run_in_user_mode = true;
		log_debug("run in user mode");
	}
}

// Declare original malloc and free
static int (*main_orig)(int, char **, char **);

static void user_main(int argc, char **argv, char **envp)
{
	// Call original main
	int ret = main_orig(argc, argv, envp);

	// Flush stdout and stderr
	fflush(stdout);
	fflush(stderr);

	// Return from user mode
	dune_ret_from_user(ret);
}

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
	struct dune_tf *tf = malloc(sizeof(struct dune_tf));
	if (!tf)
		return -ENOMEM;

	asm ("movq %%rsp, %0" : "=r" (sp));
	sp = sp - 0x10008;
	tf->rip = (unsigned long) func;
	tf->rsp = sp;
	tf->rflags = 0x0;

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

static int dune_call_user_main(void *func, int argc, char **argv, char **envp)
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

static int dune_call_user_thread(void *func, void *arg)
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

static int main_hook(int argc, char **argv, char **envp)
{
	// Initialize environment variables
	init_env();

	// Initialize VMPL
	if (!vmpl_enabled) {
		return main_orig(argc, argv, envp);
	}

	log_debug("initializing vmpl...");
	int rc = vmpl_init(true);
	if (rc) {
		log_err("failed to initialize dune");
		return rc;
	} else {
		log_debug("vmpl initialized!");
	}

	// Call original main
	if (!run_in_vmpl) {
		return main_orig(argc, argv, envp);
	}

	log_debug("entering dune mode...");
	int ret = vmpl_enter(argc, argv);
	if (ret) {
		log_err("failed to initialize dune");
	} else {
		log_debug("dune mode entered!");
	}

	// Run in user mode if requested
	if (run_in_user_mode) {
		// Call user main function in user mode
		return dune_call_user_main(&user_main, argc, argv, envp);
	}

	return main_orig(argc, argv, envp);
}

/*
 * Wrapper for __libc_start_main() that replaces the real main
 * function with our hooked version.
 */
int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
					  void (*init_dummy)(), void (*fini_dummy)(),
					  void (*ldso_dummy)())
{
	/* Save the real main function address */
	main_orig = main;

	/* Find the real __libc_start_main()... */
	typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

	/* ... and call it with our custom main function */
	return orig(main_hook, argc, argv, init_dummy, fini_dummy, ldso_dummy);
}

pid_t fork()
{
	pid_t pid;

	static typeof(&fork) fork_orig = NULL;
	if (!fork_orig)
		fork_orig = dlsym(RTLD_NEXT, "fork");

	// Call original fork
	pid = fork_orig();
	if (pid == 0) {
		if (run_in_vmpl_process) {
			log_debug("entering dune mode...");
			int ret = vmpl_init_and_enter(1, NULL);
			if (ret) {
				log_err("failed to initialize dune");
			} else {
				log_debug("dune mode entered");
			}
		}
	}

	return pid;
}

struct start_args {
	void *(*start_routine)(void *);
	void *arg;
};

static void user_thread(void *arg)
{
	struct start_args *args = (struct start_args *)arg;

	// Call user thread function
	void *rc = args->start_routine(args->arg);

	free(args); // Free args allocated in pthread_create hook before returning.

	// Return from user mode
	dune_ret_from_user(rc);
}

void *start_orig(void *arg)
{
	struct start_args *args = (struct start_args *)arg;
	log_debug("entering dune mode...");
	int ret = vmpl_enter(1, NULL);
	if (ret) {
		log_err("failed to initialize dune");
	} else {
		log_debug("dune mode entered");
	}

	if (run_in_user_mode) {
		// Call user main function in user mode
		return dune_call_user_thread(user_thread, args);
	}

	void *rc = args->start_routine(args->arg);

	free(args); // Free args allocated in pthread_create hook before returning.

	return rc;
}

int pthread_create(pthread_t *restrict res,
					 const pthread_attr_t *restrict attrp,
					 void *(*entry)(void *), void *restrict arg)
{
	static typeof(&pthread_create) pthread_create_orig = NULL;
	int rc;

	// Call original pthread_create
	if (!pthread_create_orig)
		pthread_create_orig = dlsym(RTLD_NEXT, "pthread_create");

	// Call original pthread_create if not running in VMPL thread or hotcalls is not
	// initialized yet (i.e., we are in the main thread). Otherwise, create a VMPL thread.
	// Note that we need to create a VMPL thread for hotcalls to work.
	if (!run_in_vmpl_thread || !hotcalls_initialized()) {
		return pthread_create_orig(res, attrp, entry, arg);
	}

	struct start_args *args = malloc(sizeof(struct start_args));
	args->start_routine = entry;
	args->arg = arg;

	rc = pthread_create_orig(res, attrp, start_orig, args);

	return rc;
}
