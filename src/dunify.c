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
#include "log.h"

// Declare original malloc and free
static int (*main_orig)(int, char **, char **);

int main_hook(int argc, char **argv, char **envp)
{
    printf("entering dune mode...\n");
    int ret = vmpl_enter(argc, argv);
    if (ret) {
        printf("failed to initialize dune\n");
        return ret;
    }

    printf("dune mode entered: argc=%d, argv=%p, envp=%p\n", argc, argv, envp);

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
int __libc_start_main(int (*main)(int,char **,char **), int argc, char **argv,
	void (*init_dummy)(), void(*fini_dummy)(), void(*ldso_dummy)())
{
    /* Save the real main function address */
    main_orig = main;

    /* Find the real __libc_start_main()... */
    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

    /* ... and call it with our custom main function */
    return orig(main_hook, argc, argv, init_dummy, fini_dummy, ldso_dummy);
}
