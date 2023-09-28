#ifndef __VC_H_
#define __VC_H_

#include <stdint.h>
#include <asm/msr.h>

#include "globals.h"
#include "ghcb.h"

typedef uint64_t PhysFrame;
typedef uint64_t PhysAddr;
typedef uint64_t VirtAddr;

#define LOWER_8BITS(value) ((value) & 0xFF)
#define LOWER_16BITS(value) ((value) & 0xFFFF)
#define LOWER_32BITS(value) ((value) & 0xFFFFFFFF)

#define BIT(x) (1ULL << (x))

/// 1
#define GHCB_PROTOCOL_MIN 1
/// 2
#define GHCB_PROTOCOL_MAX 2

/// 0
#define GHCB_DEFAULT_USAGE 0ULL

/// Bits zero, one and four
#define GHCB_SVSM_FEATURES (BIT(0) | BIT(1) | BIT(4))

/// 0xfff
#define GHCB_MSR_INFO_MASK 0xfff

#define GHCB_MSR_INFO(x) ((x) & GHCB_MSR_INFO_MASK)

#define GHCB_MSR_DATA(x) ((x) & ~GHCB_MSR_INFO_MASK)

// MSR protocol: SEV Information
/// 0x2
#define GHCB_MSR_SEV_INFO_REQ 0x002
/// 0x1
#define GHCB_MSR_SEV_INFO_RES 0x001
#define GHCB_MSR_PROTOCOL_MIN(x) (((x) >> 32) & 0xffff)
#define GHCB_MSR_PROTOCOL_MAX(x) (((x) >> 48) & 0xffff)

// MSR protocol: GHCB registration
/// 0x12
#define GHCB_MSR_REGISTER_GHCB_REQ 0x12
#define GHCB_MSR_REGISTER_GHCB(x) ((x) | GHCB_MSR_REGISTER_GHCB_REQ)
/// 0x13
#define GHCB_MSR_REGISTER_GHCB_RES 0x13

/* GHCB Run at VMPL Request/Response */
/// 0x16
#define GHCB_MSR_VMPL_REQ 0x016
#define GHCB_MSR_VMPL_REQ_LEVEL(x) ((x) | GHCB_MSR_VMPL_REQ)
/// 0x17
#define GHCB_MSR_VMPL_RES 0x017
#define GHCB_MSR_VMPL_RESP_VAL(v) (v >> 32)

// MSR protocol: Hypervisor feature support
/// 0x80
#define GHCB_MSR_HV_FEATURE_REQ 0x080
/// 0x81
#define GHCB_MSR_HV_FEATURE_RES 0x081
#define GHCB_MSR_HV_FEATURES(x) (GHCB_MSR_DATA(x) >> 12)

// MSR protocol: Termination request
/// 0x100
#define GHCB_MSR_TERMINATE_REQ 0x100

/// 0
#define RESCIND 0
/// 1
#define VALIDATE 1

// VMGEXIT exit codes
/// 0x27
#define GHCB_NAE_DR7_READ 0x27
/// 0x37
#define GHCB_NAE_DR7_WRITE 0x37
/// 0x6e
#define GHCB_NAE_RDTSC 0x6e
/// 0x6f
#define GHCB_NAE_RDPMC 0x6f
/// 0x72
#define GHCB_NAE_CPUID 0x72
/// 0x76
#define GHCB_NAE_INVD 0x76
/// 0x7b
#define GHCB_NAE_IOIO 0x7b
/// 0x7c
#define GHCB_NAE_MSR_PROT 0x7c
/// 0x81
#define GHCB_NAE_VMMCALL 0x81
/// 0x87
#define GHCB_NAE_RDTSCP 0x87
/// 0x89
#define GHCB_NAE_WBINVD 0x89
/// 0x80000010
#define GHCB_NAE_PSC 0x80000010
/// 0x80000011
#define GHCB_NAE_SNP_GUEST_REQUEST 0x80000011
/// 0x800000112
#define GHCB_NAE_SNP_EXTENDED_GUEST_REQUEST 0x80000012
/// 0x80000013
#define GHCB_NAE_SNP_AP_CREATION 0x80000013
/// 1
#define SNP_AP_CREATE_IMMEDIATE 1
/// 0x80000017
#define GHCB_NAE_GET_APIC_IDS 0x80000017
/// 0x80000018
#define GHCB_NAE_RUN_VMPL 0x80000018

#define GHCB_NAE_SNP_AP_CREATION_REQ(op, vmpl, apic) \
    ((op) | (((uint64_t)(vmpl)) << 16) | (((uint64_t)(apic)) << 32))

// GHCB IN/OUT instruction constants
/// Bit 9
#define IOIO_ADDR_64 BIT(9)
/// Bit 6
#define IOIO_SIZE_32 BIT(6)
/// Bit 5
#define IOIO_SIZE_16 BIT(5)
/// Bit 4
#define IOIO_SIZE_8 BIT(4)
/// Bit 0
#define IOIO_TYPE_IN BIT(0)

static inline uint64_t sev_es_rd_ghcb_msr(void)
{
	return native_read_msr(MSR_AMD64_SEV_ES_GHCB);
}

static inline void sev_es_wr_ghcb_msr(uint64_t val)
{
	uint32_t low, high;

	low  = (uint32_t)(val);
	high = (uint32_t)(val >> 32);

	native_write_msr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static inline void halt(void)
{
    __asm__ volatile("hlt");
}

static inline void vc_vmgexit(void)
{
    __asm__ volatile("rep; vmmcall");
}

void vc_run_vmpl(VMPL vmpl);

void vc_outl(uint16_t port, uint32_t value);
uint32_t vc_inl(uint16_t port);
void vc_outw(uint16_t port, uint16_t value);
uint16_t vc_inw(uint16_t port);
void vc_outb(uint16_t port, uint8_t value);
uint8_t vc_inb(uint16_t port);

void vc_init();

#endif