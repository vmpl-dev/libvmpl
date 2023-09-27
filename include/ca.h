/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

#ifndef __MY_HEADER_H__
#define __MY_HEADER_H__

#include <stdint.h>

struct Ca {
    uint8_t call_pending;
    uint8_t mem_available;
    uint8_t reserved1[6];
};

#define funcs(field, type) \
    inline type get_##field(const struct Ca *ca) { \
        return ca->field; \
    } \
    inline void set_##field(struct Ca *ca, type value) { \
        ca->field = value; \
    }

/* Function prototypes */
uint8_t get_call_pending(const struct Ca *ca);
void set_call_pending(struct Ca *ca, uint8_t value);

uint8_t get_mem_available(const struct Ca *ca);
void set_mem_available(struct Ca *ca, uint8_t value);

#endif // __MY_HEADER_H__

