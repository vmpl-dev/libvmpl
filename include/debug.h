#ifndef __DEBUG_H__
#define __DEBUG_H__

#include "vmpl.h"

#ifdef CONFIG_DUNE_BOOT
void set_debug_fd(int fd);
void dune_debug_handle_int(struct dune_config *conf);
#else
static inline void set_debug_fd(int fd) {}
static inline void dune_debug_handle_int(struct dune_config *conf) {}
#endif
#endif