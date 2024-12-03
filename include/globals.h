/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */
#ifndef __GLOBALS_H_
#define __GLOBALS_H_

#include <stdint.h>

#define BIT(n) (1ULL << (n))

// GHCB standard termination constants
/// 0
#define GHCB_REASON_CODE_SET 0
/// 0
#define GHCB_TERM_GENERAL 0
/// 1
#define GHCB_TERM_UNSUPPORTED_PROTOCOL 1
/// 2
#define GHCB_TERM_FEATURE_SUPPORT 2

// VMPL termination constants
/// 15
#define VMPL_REASON_CODE_SET 15
/// 0
#define VMPL_TERM_GENERAL 0
/// 1
#define VMPL_TERM_ENOMEM 1
/// 2
#define VMPL_TERM_UNHANDLED_VC 2
/// 3
#define VMPL_TERM_PSC_ERROR 3
/// 4
#define VMPL_TERM_SET_PAGE_ERROR 4
/// 5
#define VMPL_TERM_NO_GHCB 5
/// 6
#define VMPL_TERM_GHCB_RESP_INVALID 6
/// 7
#define VMPL_TERM_FW_CFG_ERROR 7
/// 8
#define VMPL_TERM_BIOS_FORMAT 8
/// 9
#define VMPL_TERM_NOT_VMPL0 9
/// 10
#define VMPL_TERM_VMPL0_SEV_FEATURES 10
/// 11
#define VMPL_TERM_INCORRECT_VMPL 11
/// 12
#define VMPL_TERM_VMPL1_SEV_FEATURES 12

/// 12
#define PAGE_SHIFT 12
/// BIT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
/// Page Mask (the opposite of page size minus 1)
#define PAGE_MASK (~(PAGE_SIZE - 1))

/// 21
#define PAGE_2MB_SHIFT 21
/// Bit 21
#define PAGE_2MB_SIZE (1ULL << PAGE_2MB_SHIFT)
/// Page Mask for 2MB (the opposite of 2MB page size minus 1)
#define PAGE_2MB_MASK (~(PAGE_2MB_SIZE - 1))

// CPUID
/// 0x0
#define CPUID_VENDOR_INFO 0x00000000
/// 0xb
#define CPUID_EXTENDED_TOPO 0x0000000b
/// 0xd
#define CPUID_EXTENDED_STATE 0x0000000d

// MSRs
/// 0xc0000101
#define MSR_GS_BASE 0xc0000101
/// 0xc0010130
#define MSR_GHCB 0xc0010130
/// 0xc0010131
#define MSR_SEV_STATUS 0xc0010131

// PVALIDATE and RMPADJUST related
/// 0
#define RMP_4K 0
/// 1
#define RMP_2M 1

/// Bit 8
#define VMPL_R BIT(8)
/// Bit 9
#define VMPL_W BIT(9)
/// Bit 10
#define VMPL_X_USER BIT(10)
/// Bit 11
#define VMPL_X_SUPER BIT(11)
/// Bit 16
#define VMSA_PAGE BIT(16)

/// VMPL_R | VMPL_W | VMPL_X_USER | VMPL_X_SUPER
#define VMPL_RWX (VMPL_R | VMPL_W | VMPL_X_USER | VMPL_X_SUPER)
/// VMPL_R | VMSA_PAGE
#define VMPL_VMSA (VMPL_R | VMSA_PAGE)

typedef enum {
    Vmpl0,
    Vmpl1,
    Vmpl2,
    Vmpl3,

    VmplMax,
} VMPL;

#ifndef __STR
#define __STR(x) #x
#define STR(x) __STR(x)
#endif

#ifndef __str
#define __str(x) STR(x)
#endif

#endif