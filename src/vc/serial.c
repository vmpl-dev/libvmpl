/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <stdio.h>
#include <stdbool.h>

#include "config.h"
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

void serial_out(const char *string) {
    if (!SERIAL_READY) {
        return;
    }

    const char *b = string;
    while (*b != '\0') {
        vc_outb(PORT, *b);
        b++;
    }
}

void serial_in(char *string) {
    if (!SERIAL_READY) {
        return;
    }

    while (1) {
        char b = vc_inb(PORT);
        *string = b;
        string++;

        if (b == '\n') {
            break;
        }
    }
}

#ifdef CONFIG_SERIAL_PORT
void serial_init(void) {
    vc_outb(PORT + IER, 0); /* Disable all interrupts */
    vc_outb(PORT + FCR, 0); /* Disable all FIFOs */
    vc_outb(PORT + LCR, 3); /* 8n1 */
    vc_outb(PORT + MCR, 3); /* DTR and RTS */

    unsigned short div = DIV_BASE / 115200;
    unsigned char div_lo = div & 0xFF;
    unsigned char div_hi = (div >> 8) & 0xFF;

    unsigned char c = vc_inb(PORT + LCR);
    vc_outb(PORT + LCR, c | DLAB_BIT);
    vc_outb(PORT + DLL, div_lo);
    vc_outb(PORT + DLM, div_hi);
    vc_outb(PORT + LCR, c);

    SERIAL_READY = true;
}
#endif