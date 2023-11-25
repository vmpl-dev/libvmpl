/*
 * Hook main() using LD_PRELOAD to insert a call to dune_init_and_enter
 *
 * Compile using 'gcc dunify.c -o dunify.so -fPIC -shared -ldl'
 * Then run your program as 'LD_PRELOAD=$PWD/dunify.so ./a.out'
 *
 * Adapted from: https://gist.github.com/apsun/1e144bf7639b22ff0097171fa0f8c6b1
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>

#include "vc.h"
#include "vmpl.h"
#include "log.h"

// Declare original malloc and free
static int (*main_orig)(int, char **, char **);
static void *(*original_malloc)(size_t);
static void (*original_free)(void *);
static void *(*original_mmap)(void *addr, size_t length, int prot, int flags,
							  int fd, off_t offset);
static int (*original_munmap)(void *addr, size_t length);
static pid_t (*original_fork)(void);
static pid_t (*original_vfork)(void);

// Print /proc/self/maps
void print_procmaps() {
	FILE *file = fopen("/proc/self/maps", "r");
	if (file == NULL) {
		log_err("Failed to open /proc/self/maps\n");
		return;
	}

	char *buf = malloc(1024);
	while (fgets(buf, sizeof(buf), file) != NULL) {
		printf("%s", buf);
	}

	free(buf);
	fclose(file);
}

// Hooked malloc function
void *malloc(size_t size)
{
    log_debug("Allocating %zu bytes", size);
    void *ptr = original_malloc(size);
    log_debug("Allocated %zu bytes at %p", size, ptr);
    return ptr;
}

// Hooked free function
void free(void *ptr)
{
	log_debug("Memory freed at %p", ptr);
	if (ptr == NULL) {
		log_err("Memory freded at NULL pointer!");
		print_procmaps();
	}
	original_free(ptr);
}

// Hooked mmap function
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    log_debug("Mapping %zu bytes at %p", length, addr);
    void *ptr = original_mmap(addr, length, prot, flags, fd, offset);
    log_debug("Mapped %zu bytes at %p", length, ptr);
    return ptr;
}

// Hooked munmap function
int munmap(void *addr, size_t length)
{
    log_debug("Unmapping %zu bytes at %p", length, addr);
    int ret = original_munmap(addr, length);
    log_debug("Unmapped %zu bytes at %p", length, addr);
    return ret;
}

pid_t fork(void)
{
	log_debug("Forking...");
	unsigned short cs;
	__asm__ __volatile__("movw %%cs, %0" : "=r"(cs));
	if ((cs & 0x3) == 0) {
		pid_t ret;
		wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_VMPL_REQ_LEVEL(0));
		__asm__ __volatile__("cli" ::: "memory");
		pid_t pid = original_fork();
		__asm__ __volatile__("sti" ::: "memory");
		return pid;
	}
	pid_t pid = original_fork();
	log_debug("Forked with pid %d", pid);
	return pid;
}

pid_t vfork(void)
{
	log_debug("Forking...");
	unsigned short cs;
	__asm__ __volatile__("movw %%cs, %0" : "=r"(cs));
	if ((cs & 0x3) == 0) {
		pid_t ret;
		wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_VMPL_REQ_LEVEL(0));
		__asm__ __volatile__("cli" ::: "memory");
		pid_t pid = original_vfork();
		__asm__ __volatile__("sti" ::: "memory");
		return pid;
	}
	pid_t pid = original_fork();
	log_debug("Forked with pid %d", pid);
	return pid;
}

int main_hook(int argc, char **argv, char **envp)
{
    printf("entering dune mode...\n");
	int ret = vmpl_enter(argc, argv);
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}
    return main_orig(argc, argv, envp);
}

/*
 * Wrapper for __libc_start_main() that replaces the real main
 * function with our hooked version.
 */
int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    int (*init)(int, char **, char **),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end)
{
    /* Save the real main function address */
    main_orig = main;

    /* Find the real __libc_start_main()... */
    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

    // Get the original malloc and free functions
    original_malloc = dlsym(RTLD_NEXT, "malloc");
    original_free = dlsym(RTLD_NEXT, "free");
    original_mmap = dlsym(RTLD_NEXT, "mmap");
    original_munmap = dlsym(RTLD_NEXT, "munmap");
    original_fork = dlsym(RTLD_NEXT, "fork");
    original_vfork = dlsym(RTLD_NEXT, "vfork");

    /* ... and call it with our custom main function */
    return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}
