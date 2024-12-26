#ifndef __DUNIFY_H_
#define __DUNIFY_H_

#include <stdint.h>
#include <stdbool.h>

// Mark the branch as unlikely, since we expect to run in VMPL mode most of the time.
// This is a hint to the compiler to place this branch at the end of the function.
// This is done to reduce the size of the hot path.
#define unlikely(x) __builtin_expect(!!(x), 0)
#define init_hook(name) \
    static typeof(&name) name##_orig = NULL; \
    if (unlikely(!name##_orig)) \
        name##_orig = dlsym(RTLD_NEXT, #name);

extern bool hotcalls_enabled;
extern bool run_in_vmpl;
extern bool run_in_vmpl_process;
extern bool run_in_vmpl_thread;

#endif // !__DUNIFY_H_