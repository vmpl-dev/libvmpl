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
#include <pthread.h>

#include "vc.h"
#include "vmpl.h"
#include "mm.h"
#include "log.h"

// Declare original malloc and free
static int (*main_orig)(int, char **, char **);

static void print_procmaps()
{
	FILE *fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		log_err("failed to open /proc/self/maps");
		return;
	}

	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	while ((read = getline(&line, &len, fp)) != -1) {
		printf("%s", line);
	}
	fclose(fp);
	fflush(stdout);
}

static void get_fs_base(char *name)
{
	unsigned long fs_base0, fs_base1, fs_base2;

	if (arch_prctl(ARCH_GET_FS, &fs_base0) == -1) {
		log_err("arch_prctl failed");
	}

	__asm__ volatile("mov %%fs:0, %0\n" : "=r"(fs_base1));
	__asm__ volatile("rdfsbase %0\n" : "=r"(fs_base2));
	if (fs_base0 != fs_base1 || fs_base0 != fs_base2) {
		log_err("fs_base0: %lx, fs_base1: %lx, fs_base2: %lx", fs_base0,
				fs_base1, fs_base2);
		log_err("fs_base0!= fs_base1 || fs_base0!= fs_base2");
	} else {
		log_success("%s fs_base=%lx", name, fs_base0);
	}
}

static int main_hook(int argc, char **argv, char **envp)
{
	if (!getenv("RUN_IN_VMPL")) {
		return main_orig(argc, argv, envp);
	}

	print_procmaps();
	get_fs_base("main_hook");
	log_debug("entering dune mode...\n");
	int ret = vmpl_enter(argc, argv);
	if (ret) {
		log_err("failed to initialize dune\n");
	} else {
		log_debug("dune mode entered: argc=%d, argv=%p, envp=%p\n", argc, argv,
			   envp);
	}

	// Print environment variables
	for (char **env = envp; *env != 0; env++) {
		char *thisEnv = *env;
		log_debug("%s", thisEnv);
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

#undef fork
pid_t fork()
{
	pid_t pid;

	static typeof(&fork) fork_orig = NULL;
	if (!fork_orig)
		fork_orig = dlsym(RTLD_NEXT, "fork");

	// Call original fork
	if (!getenv("RUN_IN_VMPL_PROCESS")) {
		return fork_orig();
	}

	pid = fork_orig();
	if (pid == 0) {
		log_debug("entering dune mode...\n");
		int ret = vmpl_enter(1, NULL);
		if (ret) {
			log_err("failed to initialize dune\n");
			return -1;
		}

		log_debug("dune mode entered\n");
	}

	return pid;
}

struct start_args {
	void *(*start_routine)(void *);
	void *arg;
};

void *start_orig(void *arg)
{
	struct start_args *args = (struct start_args *)arg;
	log_debug("entering dune mode...\n");
	int ret = vmpl_enter(1, NULL);
	if (ret) {
		log_err("failed to initialize dune\n");
		return NULL;
	}

	log_debug("dune mode entered\n");
	return args->start_routine(args->arg);
}

#undef pthread_create
int pthread_create(pthread_t *restrict res,
					 const pthread_attr_t *restrict attrp,
					 void *(*entry)(void *), void *restrict arg)
{
	static typeof(&pthread_create) pthread_create_orig = NULL;
	int rc;

	// Call original pthread_create
	if (!pthread_create_orig)
		pthread_create_orig = dlsym(RTLD_NEXT, "pthread_create");

	if (!getenv("RUN_IN_VMPL_THREAD")) {
		return pthread_create_orig(res, attrp, entry, arg);
	}

	struct start_args *args = malloc(sizeof(struct start_args));
	args->start_routine = entry;
	args->arg = arg;

	rc = pthread_create_orig(res, attrp, start_orig, args);
	free(args);

	return rc;
}

#undef sbrk
int brk(void *addr)
{
	static typeof(&brk) brk_orig = NULL;
	if (!brk_orig)
		brk_orig = dlsym(RTLD_NEXT, "sbrk");

	if (!getenv("RUN_IN_VMPL_MMAP")) {
		return brk_orig(addr);
	}

	// TODO: Intercept sbrk

	return brk_orig(addr);
}

void *sbrk(intptr_t increment)
{
	static typeof(&sbrk) sbrk_orig = NULL;
	if (!sbrk_orig)
		sbrk_orig = dlsym(RTLD_NEXT, "sbrk");

	if (!getenv("RUN_IN_VMPL_MMAP")) {
		return sbrk_orig(increment);
	}

	// TODO: Intercept sbrk

	return sbrk_orig(increment);
}

#undef mmap
void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
	// Call original mmap
	static typeof(&mmap) mmap_orig = NULL;
	if (!mmap_orig)
		mmap_orig = dlsym(RTLD_NEXT, "mmap");
	
	if (!getenv("RUN_IN_VMPL_MMAP")) {
		return mmap_orig(addr, length, prot, flags, fd, offset);
	}

	// Intercept mmap calls when running in VMPL, such that we can handle the memory allocation
	// in the guest process.
	if (addr == NULL) {
		if (flags & MAP_FIXED) {
			// Allocate memory in the guest process
			void *guest_addr = vmpl_alloc(length);
			if (guest_addr == NULL) {
				log_err("failed to allocate memory in guest process");
				return -1;
			}

			return (int)guest_addr;
		}
	}

	// TODO: Handle mmap

	return vmpl_mmap(addr, length, prot, flags, fd, offset);
}

#undef mremap
void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */)
{
	// Call original mremap
	static typeof(&mremap) mremap_orig = NULL;
	if (!mremap_orig)
		mremap_orig = dlsym(RTLD_NEXT, "mremap");
	
	if (!getenv("RUN_IN_VMPL_MMAP")) {
		return mremap_orig(old_address, old_size, new_size, flags);
	}

	// Intercept mremap calls when running in VMPL, such that we can handle the memory allocation
	// in the guest process.

	// TODO: Handle mremap

	return vmpl_mremap(old_address, old_size, new_size, flags);
}

#undef munmap
int munmap(void *addr, size_t length)
{
	// Call original munmap
	static typeof(&munmap) munmap_orig = NULL;
	if (!munmap_orig)
		munmap_orig = dlsym(RTLD_NEXT, "munmap");
	
	if (!getenv("RUN_IN_VMPL_MMAP")) {
		return munmap_orig(addr, length);
	}

	// Intercept munmap calls when running in VMPL, such that we can handle the memory allocation
	// in the guest process.

	// TODO: Handle munmap

	return vmpl_munmap(addr, length);
}