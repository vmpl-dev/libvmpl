#ifndef _SEIME_H_
#define _SEIME_H_

#include <stdbool.h>
#include <stddef.h>

int setup_seimi(int dune_fd);
void *sa_alloc(size_t length, bool need_ro, long *offset);
bool sa_free(void *addr, size_t length);

#endif