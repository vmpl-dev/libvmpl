#ifndef __VC_H_
#define __VC_H_

#include <stdint.h>

#include "globals.h"
#include "ghcb.h"

void vc_run_vmpl(VMPL vmpl);

void vc_outl(uint16_t port, uint32_t value);
uint32_t vc_inl(uint16_t port);
void vc_outw(uint16_t port, uint16_t value);
uint16_t vc_inw(uint16_t port);
void vc_outb(uint16_t port, uint8_t value);
uint8_t vc_inb(uint16_t port);

void vc_init();

#endif