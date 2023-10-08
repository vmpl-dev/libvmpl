/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <stdio.h>
#include <stdbool.h>

#include "globals.h"
#include "vc.h"
#include "serial.h"

#define TTYS0 0x3f8
#define DIV_BASE 115200
#define DLAB_BIT BIT(7)

#define IER 1
#define FCR 2
#define LCR 3
#define MCR 4

#define DLL 0
#define DLM 1

unsigned short PORT = TTYS0;

bool SERIAL_READY = false;

#ifdef VERBOSE
void serial_out(const char *string) {
    if (!SERIAL_READY) {
        return;
    }

    const char *c = string;
    while (*c != '\0') {
        outb(PORT, *c);
        c++;
    }
}

void serial_in(char *string) {
    if (!SERIAL_READY) {
        return;
    }

    while (1) {
        char b = inb(PORT);
        *string = b;
        string++;

        if (b == '\n') {
            break;
        }
    }
}
#else
void serial_out(const char *string) {}
void serial_init(void) {}
#endif

#ifdef VERBOSE
void serial_init(void) {
    outb(PORT + IER, 0); /* Disable all interrupts */
    outb(PORT + FCR, 0); /* Disable all FIFOs */
    outb(PORT + LCR, 3); /* 8n1 */
    outb(PORT + MCR, 3); /* DTR and RTS */

    unsigned short div = DIV_BASE / 115200;
    unsigned char div_lo = div & 0xFF;
    unsigned char div_hi = (div >> 8) & 0xFF;

    unsigned char c = inb(PORT + LCR);
    outb(PORT + LCR, c | DLAB_BIT);
    outb(PORT + DLL, div_lo);
    outb(PORT + DLM, div_hi);
    outb(PORT + LCR, c);

    SERIAL_READY = true;
}
#endif
