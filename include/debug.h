#ifndef __DEBUG_H__
#define __DEBUG_H__

#include "vmpl.h"

void set_debug_fd(int fd);
void dune_debug_handle_int(struct dune_config *conf);
#endif