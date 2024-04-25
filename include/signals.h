// Contents: signal related functions
// This file is not used in the project
#ifndef __SIGNAL_H__
#define __SIGNAL_H__

#pragma once
#include "config.h"

#ifdef CONFIG_VMPL_SIGNAL
void setup_signal(void);
#else
static inline void setup_signal(void) { }
#endif

#endif