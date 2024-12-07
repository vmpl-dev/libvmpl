/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */
#ifndef __GHCB_H_
#define __GHCB_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "globals.h"
#include "mm.h"

#define GHCB_VERSION_1 1
#define GHCB_USAGE 0
#define SHARED_BUFFER_SIZE 2032

#define MSR_AMD64_SEV_ES_GHCB         0xc0010130

// #define BIT(nr) (1UL << (nr))

// Calculates the offset of a field within a structure
#define offset_of(type, field) ((size_t)(&((type *)0)->field))

typedef struct Ghcb {
    uint8_t reserved1[203];
    uint8_t cpl;
    uint8_t reserved2[300];
    uint64_t rax;
    uint8_t reserved3[264];
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint8_t reserved4[112];
    uint64_t sw_exit_code;
    uint64_t sw_exit_info_1;
    uint64_t sw_exit_info_2;
    uint64_t sw_scratch;
    uint8_t reserved5[56];
    uint64_t xcr0;
    uint8_t valid_bitmap[16];
    uint8_t reserved6[1024];
    uint8_t shared_buffer[SHARED_BUFFER_SIZE];
    uint8_t reserved7[10];
    uint16_t version;
    uint32_t usage;
} Ghcb;

void dump_ghcb(struct Ghcb *ghcb);

inline void set_offset_valid(Ghcb* ghcb, size_t offset) {
    size_t idx = (offset / 8) / 8;
    size_t bit = (offset / 8) % 8;
    ghcb->valid_bitmap[idx] |= BIT(bit);
}

inline bool is_offset_valid(const Ghcb* ghcb, size_t offset) {
    size_t idx = (offset / 8) / 8;
    size_t bit = (offset / 8) % 8;
    return (ghcb->valid_bitmap[idx] & BIT(bit)) != 0;
}

#define GHCB_FNS(name)                                       \
    inline void ghcb_set_##name(Ghcb *ghcb, uint64_t value)  \
    {                                                        \
        ghcb->name = value;                                  \
        set_offset_valid(ghcb, offset_of(Ghcb, name));       \
    }                                                        \
    inline uint64_t ghcb_get_##name(const Ghcb *ghcb)        \
    {                                                        \
        return ghcb->name;                                   \
    }                                                        \
    inline bool ghcb_is_##name##_valid(const Ghcb *ghcb)     \
    {                                                        \
        return is_offset_valid(ghcb, offset_of(Ghcb, name)); \
    }

GHCB_FNS(rax)
GHCB_FNS(rbx)
GHCB_FNS(rcx)
GHCB_FNS(rdx)
GHCB_FNS(xcr0)
GHCB_FNS(sw_exit_code)
GHCB_FNS(sw_exit_info_1)
GHCB_FNS(sw_exit_info_2)
GHCB_FNS(sw_scratch)

inline uint16_t ghcb_get_version(Ghcb* self) {
    return self->version;
}

inline void ghcb_set_version(Ghcb* self, uint16_t version) {
    self->version = version;
}

inline uint32_t ghcb_get_usage(Ghcb* self) {
    return self->usage;
}

inline void ghcb_set_usage(Ghcb* self, uint32_t usage) {
    self->usage = usage;
}

inline void ghcb_clear(Ghcb* ghcb) {
    ghcb->sw_exit_code = 0;
    memset(ghcb->valid_bitmap, 0, sizeof(ghcb->valid_bitmap));
}

inline void ghcb_get_shared_buffer(Ghcb* ghcb, uint8_t* data, size_t len) {
    if (len > SHARED_BUFFER_SIZE) {
        return;
    }

    memcpy(data, ghcb->shared_buffer, len);
}

inline void ghcb_set_shared_buffer(Ghcb* ghcb, const uint8_t* data, size_t len) {
    if (len > SHARED_BUFFER_SIZE) {
        return;
    }

    memcpy(ghcb->shared_buffer, data, len);
    ghcb_set_sw_scratch(ghcb, (uintptr_t)pgtable_va_to_pa(ghcb->shared_buffer));
}

_Static_assert(sizeof(struct Ghcb) == PAGE_SIZE, "Ghcb size is not equal to PAGE_SIZE");

#endif