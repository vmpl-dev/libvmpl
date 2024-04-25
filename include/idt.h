#ifndef __IDT_H__
#define __IDT_H__

#include <stdint.h>
#include <stddef.h>

#include "sys.h"

#define IDT_ENTRIES 256
#define ISR_LEN 16

#define IDTD_P 0x80
#define IDTD_TRAP_GATE 0xF
#define IDTD_INTERRUPT_GATE 0xE
#define IDTD_CPL3 0x60

extern struct idtd idt[IDT_ENTRIES];
extern void dump_idt(struct idtd *idt);
extern void setup_idt(void);
#endif