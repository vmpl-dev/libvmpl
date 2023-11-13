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

#include <vmpl/vmpl.h>
#include <vmpl/log.h>

// Declare original malloc and free
static int (*main_orig)(int, char **, char **);
static void* (*original_malloc)(size_t);
static void (*original_free)(void*);
static void* (*original_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
static int (*original_munmap)(void *addr, size_t length);

// Hooked malloc function
void* malloc(size_t size)
{
    log_info("Allocating %zu bytes", size);
    void* ptr = original_malloc(size);
    log_info("Allocated %zu bytes at %p", size, ptr);
    return ptr;
}

// Hooked free function
void free(void* ptr)
{
	log_info("Freeing %zu bytes");
	original_free(ptr);
	log_info("Memory freed at %p", ptr);
}

// Hooked mmap function
void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    log_info("Mapping %zu bytes at %p", length, addr);
    void* ptr = original_mmap(addr, length, prot, flags, fd, offset);
    log_info("Mapped %zu bytes at %p", length, ptr);
    return ptr;
}

// Hooked munmap function
int munmap(void* addr, size_t length)
{
    log_info("Unmapping %zu bytes at %p", length, addr);
    int ret = original_munmap(addr, length);
    log_info("Unmapped %zu bytes at %p", length, addr);
    return ret;
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

    /* ... and call it with our custom main function */
    return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}
