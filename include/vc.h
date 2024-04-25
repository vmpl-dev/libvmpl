#ifndef __VC_H_
#define __VC_H_

#include <stdint.h>

#include "config.h"
#include "sys.h"
#include "globals.h"
#include "ghcb.h"
#include "percpu.h"

#define RUN_VMPL Vmpl0

#define LOWER_8BITS(value) ((value) & 0xFF)
#define LOWER_16BITS(value) ((value) & 0xFFFF)
#define LOWER_32BITS(value) ((value) & 0xFFFFFFFF)

// #define BIT(x) (1ULL << (x))

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

// MSR protocol: CPUID Request
/// 0x004
#define GHCB_MSR_CPUID_REQ 0x004
#define GHCB_MSR_CPUID_REQ_EAX(x) ((0x00 << 30) | GHCB_MSR_CPUID_REQ)
#define GHCB_MSR_CPUID_REQ_EBX(x) ((0x01 << 30) | GHCB_MSR_CPUID_REQ)
#define GHCB_MSR_CPUID_REQ_ECX(x) ((0x02 << 30) | GHCB_MSR_CPUID_REQ)
#define GHCB_MSR_CPUID_REQ_EDX(x) ((0x03 << 30) | GHCB_MSR_CPUID_REQ)
/// 0x005
#define GHCB_MSR_CPUID_RES 0x005
#define GHCB_MSR_CPUID_RES_VAL(v) (GHCB_MSR_DATA(v) >> 32)

// MSR protocol: Preferred GHCB GPA
/// 0x010
#define GHCB_MSR_PREFERRED_GHCB_REQ 0x010
#define GHCB_MSR_PREFERRED_GHCB(x) ((x) | GHCB_MSR_PREFERRED_GHCB_REQ)
/// 0x011
#define GHCB_MSR_PREFERRED_GHCB_RES 0x011
#define GHCB_MSR_PREFERRED_GHCB_VAL(v) (GHCB_MSR_DATA(v) >> 12)

// MSR protocol: GHCB registration
/// 0x12
#define GHCB_MSR_REGISTER_GHCB_REQ 0x12
#define GHCB_MSR_REGISTER_GHCB(x) ((x) | GHCB_MSR_REGISTER_GHCB_REQ)
/// 0x13
#define GHCB_MSR_REGISTER_GHCB_RES 0x13

// MSR protocol: SNP Page State Change
/// 0x14
#define GHCB_MSR_SNP_PSC_REQ 0x014
#define GHCB_MSR_SNP_PSC(x, op) ((op << 52) | (x & 0xfff) | GHCB_MSR_SNP_PSC_REQ)
#define GHCB_MSR_SNP_PSC_SHARED(x) GHCB_MSR_SNP_PSC(x, SNP_PSC_OP_ASSIGN_SHARED)
#define GHCB_MSR_SNP_PSC_PRIVATE(x) GHCB_MSR_SNP_PSC(x, SNP_PSC_OP_ASSIGN_PRIVATE)
/// 0x15
#define GHCB_MSR_SNP_PSC_RES 0x015
#define GHCB_MSR_SNP_PSC_VAL(v) (v >> 32)

// 0x0001 - Page assignment, Private
#define SNP_PSC_OP_ASSIGN_PRIVATE 0x0001
// 0x0002 - Page assignment, Shared
#define SNP_PSC_OP_ASSIGN_SHARED 0x0002

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
/// 0x0 General termination request
#define GHCB_MSR_TERMINATE_GENERAL 0x0
/// 0x1 SEV-ES/GHCB Protocol range is not supported.
#define GHCB_MSR_TERMINATE_PROTOCOL_RANGE 0x1
/// 0x2 SEV-SNP features not supported
#define GHCB_MSR_TERMINATE_SNP_FEATURES 0x2

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
/// 0x80000001
#define GHCB_NAE_MMIO_READ 0x80000001
/// 0x80000002
#define GHCB_NAE_MMIO_WRITE 0x80000002
/// 0x80000003
#define GHCB_NAE_NMI_COMPLETE 0x80000003
/// 0x80000004
#define GHCB_NAE_AP_RESET_HOLD 0x80000004
/// 0x80000005
#define GHCB_NAE_AP_JUMP_TABLE 0x80000005
/// 0x80000010
#define GHCB_NAE_PSC 0x80000010
/// 0x80000011
#define GHCB_NAE_SNP_GUEST_REQUEST 0x80000011
/// 0x80000012
#define GHCB_NAE_SNP_EXTENDED_GUEST_REQUEST 0x80000012
/// 0x80000013
#define GHCB_NAE_SNP_AP_CREATION 0x80000013
/// 1
#define SNP_AP_CREATE_IMMEDIATE 1
/// 0x80000014
#define GHCB_NAE_HV_DOORBELL_PAGE 0x80000014
/// 0x80000015
#define GHCB_NAE_HV_IPI 0x80000015
/// 0x80000016
#define GHCB_NAE_HV_TIMER 0x80000016
/// 0x80000017
#define GHCB_NAE_GET_APIC_IDS 0x80000017
/// 0x80000018
#define GHCB_NAE_RUN_VMPL 0x80000018
/// 0x8000fffd
#define GHCB_NAE_HV_FEATURES 0x8000fffd
/// 0x8000fffe
#define GHCB_NAE_TERMINATE_REQUEST 0x8000fffe
/// 0x8000ffff
#define GHCB_NAE_UNSUPPORTED_EVENT 0x8000ffff

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
	return rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static inline void sev_es_wr_ghcb_msr(uint64_t val)
{
	wrmsrl(MSR_AMD64_SEV_ES_GHCB, val);
}

static inline void vc_vmgexit(void)
{
#if defined(__GNUC__)
#if __GNUC__ < 12
    __asm__ volatile("rep; vmmcall");
#else
    __asm__ volatile("vmgexit");
#endif
#else
#if defined(__clang__)
    __asm__ volatile("rep; vmmcall");
#else
#error "Unsupported compiler"
#endif
#endif
}

void vc_run_vmpl(VMPL vmpl);

void vc_outl(uint16_t port, uint32_t value);
uint32_t vc_inl(uint16_t port);
void vc_outw(uint16_t port, uint16_t value);
uint16_t vc_inw(uint16_t port);
void vc_outb(uint16_t port, uint8_t value);
uint8_t vc_inb(uint16_t port);

#ifdef CONFIG_VMPL_GHCB
int vc_init(struct dune_percpu *percpu);
int vc_init_percpu(struct dune_percpu *percpu);
#else
static inline int vc_init(struct dune_percpu *percpu)
{
    return 0;
}
#endif

#endif