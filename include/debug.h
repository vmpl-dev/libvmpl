#ifndef __DEBUG_H__
#define __DEBUG_H__

#include "vmpl.h"

#ifdef CONFIG_DUNE_BOOT
void dune_debug_handle_int(struct dune_config *conf);
#else
static inline void dune_debug_handle_int(struct dune_config *conf) {}
#endif
#endif