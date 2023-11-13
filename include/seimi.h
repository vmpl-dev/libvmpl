#ifndef _SEIME_H_
#define _SEIME_H_

#include <stdbool.h>
#include <stddef.h>

#ifdef CONFIG_VMPL_SEIMI
int setup_seimi(int dune_fd);
#else
static inline int setup_seimi(int dune_fd)
{
    return 0;
}
#endif
void *sa_alloc(size_t length, bool need_ro, long *offset);
bool sa_free(void *addr, size_t length);

#endif