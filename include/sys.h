#ifndef __SYS_H_
#define __SYS_H_

#include <stdint.h>
#include <stdbool.h>
#include <cpuid.h>

#define BIT(bit) (1ULL << (bit))

// 3.1 System-Control Registers

// 3.1.1 CR0 Register
#define CR0_PE BIT(0) /* Protected mode enable */
#define CR0_MP BIT(1) /* Monitor coprocessor */
#define CR0_EM BIT(2) /* Emulate FPU */
#define CR0_TS BIT(3) /* Task switched */
#define CR0_ET BIT(4) /* Extension type */
#define CR0_NE BIT(5) /* Numeric error */
#define CR0_WP BIT(16) /* Write protect */
#define CR0_AM BIT(18) /* Alignment mask */
#define CR0_NW BIT(29) /* Not write-through */
#define CR0_CD BIT(30) /* Cache disable */
#define CR0_PG BIT(31) /* Paging enable */

// 3.1.2 CR2 and CR3 Registers
#define CR3_PWT BIT(3) /* Page-level write-through */
#define CR3_PCD BIT(4) /* Page-level cache disable */

// 3.1.3 CR4 Register
#define CR4_VME BIT(0) /* Virtual-8086 mode extensions */
#define CR4_PSE BIT(4) /* Page size extensions */
#define CR4_PAE BIT(5) /* Physical address extensions */
#define CR4_MCE BIT(6) /* Machine check exception */
#define CR4_PGE BIT(7) /* Page global enable */
#define CR4_PCE BIT(8) /* Performance monitoring counter enable */
#define CR4_OSFXSR BIT(9) /* OS support for FXSAVE and FXRSTOR instructions */
#define CR4_OSXMMEXCPT BIT(10) /* OS support for unmasked SIMD floating-point exceptions */
#define CR4_VMXE BIT(13) /* Virtual machine extensions enable */
#define CR4_SMXE BIT(14) /* Safer mode extensions enable */
#define CR4_FSGSBASE BIT(16) /* Enable the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE */
#define CR4_PCIDE BIT(17) /* Process-context identifiers enable */
#define CR4_OSXSAVE BIT(18) /* XSAVE and processor extended states enable */
#define CR4_SMEP BIT(20) /* Supervisor mode execution protection enable */
#define CR4_SMAP BIT(21) /* Supervisor mode access prevention enable */
#define CR4_PKE BIT(22) /* Protection-key enable */

// 3.1.5 CR8 (Task Priority Register, TPR)
#define CR8_TPR BIT(4) /* Task priority register */

// 3.1.6 RFLAGS Register
#define RFLAGS_CF BIT(0) /* Carry flag */
#define RFLAGS_PF BIT(2) /* Parity flag */
#define RFLAGS_AF BIT(4) /* Auxiliary carry flag */
#define RFLAGS_ZF BIT(6) /* Zero flag */
#define RFLAGS_SF BIT(7) /* Sign flag */
#define RFLAGS_TF BIT(8) /* Trap flag */
#define RFLAGS_IF BIT(9) /* Interrupt enable flag */
#define RFLAGS_DF BIT(10) /* Direction flag */
#define RFLAGS_OF BIT(11) /* Overflow flag */
#define RFLAGS_IOPL BIT(12) | BIT(13) /* I/O privilege level */
#define RFLAGS_NT BIT(14) /* Nested task */
#define RFLAGS_RF BIT(16) /* Resume flag */
#define RFLAGS_VM BIT(17) /* Virtual 8086 mode */
#define RFLAGS_AC BIT(18) /* Alignment check */
#define RFLAGS_VIF BIT(19) /* Virtual interrupt flag */
#define RFLAGS_VIP BIT(20) /* Virtual interrupt pending */
#define RFLAGS_ID BIT(21) /* ID flag */

// 3.1.7 Extended Feature Enable Register (EFER)
#define EFER	   0xc0000080 /* MSR number */
#define EFER_SCE   BIT(0) /* System-call extension */
#define EFER_LME   BIT(8) /* Long mode enable */
#define EFER_LMA   BIT(10) /* Long mode active */
#define EFER_NXE   BIT(11) /* No-execute enable */
#define EFER_FFXSR BIT(14) /* Fast FXSAVE/FXRSTOR */
#define EFER_SVME  BIT(12) /* Secure virtual machine enable */
#define EFER_LMSLE BIT(13) /* Long mode segment limit enable */
#define EFER_FFXSR BIT(14) /* Fast FXSAVE/FXRSTOR */
#define EFER_TCE   BIT(15) /* Translation cache extension */
#define EFER_MCOMMIT BIT(17) /*  Enable MCOMMIT instruction */
#define EFER_INTWB BIT(18) /* Interruptible WBINVD/WBNOINVD enable */
#define EFER_UAIE BIT(20) // Upper Address Ignore Enable
#define EFER_AIBRSE BIT(21) // Automatic IBRS Enable

// 3.1.8 Extended Control Registers (XCRn)
#define XCR0_X87 BIT(0) /* x87 state */
#define XCR0_SSE BIT(1) /* SSE state */
#define XCR0_AVX BIT(2) /* AVX state */
#define XCR0_BNDREG BIT(3) /* MPX BNDREGS state */
#define XCR0_BNDCSR BIT(4) /* MPX BNDCSR state */
#define XCR0_OPMASK BIT(5) /* AVX-512 opmask state */
#define XCR0_ZMM_Hi256 BIT(6) /* AVX-512 ZMM_Hi256 state */
#define XCR0_Hi16_ZMM BIT(7) /* AVX-512 Hi16_ZMM state */
#define XCR0_PKRU BIT(9) /* Protection Key state */

// 3.2 Model-Specific Registers (MSRs)

// 3.2.1 System Configuration Register (SYSCFG)
#define SYSCFG_MSR 0xc0011023 /* MSR number */
#define SYSCFG_HMKE BIT(26) // HostMultiKeyMemEncrModeEn R/W
#define SYSCFG_VMPLE BIT(25) // VMPLEn R/W
#define SYSCFG_SNPE BIT(24) // SecureNestedPagingEn R/W
#define SYSCFG_MEME BIT(23) // MemEncryptionModeEn R/W
#define SYSCFG_FWB BIT(22) // Tom2ForceMemTypeWB R/W
#define SYSCFG_TOM2 BIT(21) // MtrrTom2En R/W
#define SYSCFG_MVDM BIT(20) // MtrrVarDramEn R/W
#define SYSCFG_MFDM BIT(19) // MtrrFixDramModEn R/W
#define SYSCFG_MFDE BIT(18) // MtrrFixDramEn R/W

// 3.2.2 System-Linkage Registers
#define MSR_STAR 0xc0000081
#define MSR_LSTAR 0xc0000082
#define MSR_CSTAR 0xc0000083
#define MSR_SFMASK 0xc0000084
#define MSR_FS_BASE 0xc0000100
#define MSR_GS_BASE 0xc0000101
#define MSR_KERNEL_GS_BASE 0xc0000102
#define MSR_SYSENTER_CS 0x174
#define MSR_SYSENTER_ESP 0x175
#define MSR_SYSENTER_EIP 0x176

// 3.2.3 Memory-Typing Registers
#define MTRR_CAP_REG 0x0FE
#define MTRR_DEF_TYPE_REG 0x2FF
#define MTRR_PHYS_BASE(n) (0x200 + 2 * (n))
#define MTRR_PHYS_MASK(n) (0x201 + 2 * (n))
#define MTRR_FIX(n) (0x250 + (n))
#define PAT_REG 0x277
#define TOP_MEM_REG 0x1FED4
#define TOP_MEM2_REG 0x1FED5

// 3.2.4 Debug-Extension Registers
#define MSR_DEBUG_CTL 0x1d9 /* MSR number */
#define DEBUG_CTL_LBR (1 << 0) /* Last-Branch Record */
#define DEBUG_CTL_BTF (1 << 1) /* Branch Trace Store */
#define DEBUG_CTL_TR (1 << 6) /* Trace Enable */
#define DEBUG_CTL_BTS (1 << 7) /* Branch Trace Store */

#define DR0 0
#define DR1 1
#define DR2 2
#define DR3 3
#define DR6 6
#define DR7 7

#define __read_dr(reg) ({ \
    uint64_t value; \
    __asm__ volatile("mov %%" #reg ", %0" : "=r" (value)); \
    value; \
})

#define __write_dr(reg, value) do { \
    __asm__ volatile("mov %0, %%" #reg : : "r" (value)); \
} while (0)

#define read_dr(reg) __read_dr(DR##reg)
#define write_dr(reg, value) __write_dr(DR##reg, value)

// 3.2.5 Performance-Monitoring Registers

// 3.2.6 Machine-Check Registers

// 3.2.7 Shadow Stack Registers
#define CPUID_CET_SS 0x00000007
static inline bool cpu_supports_cet_ss(void)
{
    unsigned int eax, ebx, ecx, edx;
    __cpuid(CPUID_CET_SS, eax, ebx, ecx, edx);
    return (ecx & BIT(7)) != 0;
}

// 3.2.8 Extended State Save MSRs 
#define CPUID_EXTENDED_STATE 0x0000000D
#define CET_S (1 << 12)  // Enables the CET_U state component. R/W
#define CET_U (1 << 11)  // CET_U Enables the CET_S state component. R/W

static inline bool cpu_supports_xsaves(void)
{
    unsigned int eax, ebx, ecx, edx;
    __cpuid(CPUID_EXTENDED_STATE, eax, ebx, ecx, edx);
    return (eax & BIT(3)) != 0;
}
// 3.2.9 Speculation Control MSRs 

// 3.2.10 Hardware Configuration Register (HWCR)

#define read_cr(reg) ({ \
    uint64_t value; \
    asm volatile("mov %%" #reg ", %0" : "=r"(value) : : "memory"); \
    value; \
})

#define write_cr(reg, value) do { \
    asm volatile("mov %0, %%" #reg : : "r"(value) : "memory"); \
} while (0)

#define read_cr0() read_cr(cr0)
#define write_cr0(value) write_cr(cr0, value)
#define read_cr2() read_cr(cr2)
#define write_cr2(value) write_cr(cr2, value)
#define read_cr3() read_cr(cr3)
#define write_cr3(value) write_cr(cr3, value)
#define read_cr4() read_cr(cr4)
#define write_cr4(value) write_cr(cr4, value)
#define read_xfer() read_cr(xfer)
#define write_xfer(value) write_cr(xfer, value)
#define read_xcr0() read_cr(xcr0)
#define write_xcr0(value) write_cr(xcr0, value)

// Read MSR
static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t lo;
    uint32_t hi;

    __asm__ __volatile__("rdmsr"
                         : "=a"(lo), "=d"(hi)
                         : "c"(msr)
                         : "memory");

    return ((uint64_t)hi << 32) | lo;
}

// Write to MSR a given value
static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t lo = (uint32_t)value;
    uint32_t hi = (uint32_t)(value >> 32);

    __asm__ __volatile__("wrmsr"
                         :
                         : "c"(msr), "a"(lo), "d"(hi)
                         : "memory");
}

// Pause instruction
#ifndef __x86_64__
static inline int pause() {
    __asm__("pause");
    return 0;
}
#endif

// Halt instruction
static inline void halt() {
    __asm__("hlt");
}

// 1
#define PVALIDATE_FAIL_INPUT 1
// 6
#define PVALIDATE_FAIL_SIZE_MISMATCH 6

// 15
#define PVALIDATE_RET_MAX 15
// 16
#define PVALIDATE_CF_SET 16
// 17
#define PVALIDATE_RET_ERR 17

// Pvalidate a given memory region
static inline pvalidate(uint64_t va, uint32_t page_size, uint32_t validation) {
    uint32_t ret;
    uint32_t carry;

    __asm__ volatile(".byte 0xf2,0x0f,0x01,0xff\n"
                 "xor %%rcx, %%rcx\n"
                 "jnc 1f\n"
                 "inc %%rcx\n"
                 "1:\n"
                 : "=a"(ret), "=c"(carry)
                 : "a"(va), "c"(page_size), "d"(validation)
                 : "memory");

    if (ret > PVALIDATE_RET_MAX) {
        ret = PVALIDATE_RET_ERR;
    } else if (ret == 0 && carry > 0) {
        ret = PVALIDATE_CF_SET;
    }

    return ret;
}

// 1
#define RMPADJUST_FAIL_INPUT 1
// 2
#define RMPADJUST_FAIL_PERMISSION 2
// 6
#define RMPADJUST_FAIL_SIZE_MISMATCH 6

// Update RMP (Reverse Map Table) with new attributes
static inline uint32_t rmpadjust(uint64_t va, uint32_t page_size, uint64_t attrs) {
    uint32_t ret;

    __asm__ __volatile__(".byte 0xf3,0x0f,0x01,0xfe"
                         : "=a"(ret)
                         : "a"(va), "c"(page_size), "d"(attrs)
                         : "memory");

    return ret;
}

// Flush everything for the ASID, including Global entries
static inline void invlpgb_all(void) {
    uint32_t rax = BIT(3);

    __asm__ __volatile__(".byte 0x0f,0x01,0xfe"
                         :
                         : "a"(rax), "c"(0), "d"(0)
                         : "memory");
}

static inline void tlbsync(void) {
    __asm__ __volatile__(".byte 0x0f,0x01,0xff"
                         :
                         :
                         : "memory");
}

// Compare and exchange
static inline uint64_t cmpxchg(uint64_t cmpval, uint64_t newval, uint64_t va) {
    uint64_t ret;

    __asm__ __volatile__("lock cmpxchgq %1, %2"
                         : "=a"(ret)
                         : "q"(newval), "m"(*(volatile uint64_t *)va), "0"(cmpval)
                         : "memory");

    return ret;
}

#endif