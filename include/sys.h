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
// #define MSR_STAR 0xc0000081
// #define MSR_LSTAR 0xc0000082
// #define MSR_CSTAR 0xc0000083
// #define MSR_SFMASK 0xc0000084
// #define MSR_FS_BASE 0xc0000100
// #define MSR_GS_BASE 0xc0000101
// #define MSR_KERNEL_GS_BASE 0xc0000102
// #define MSR_SYSENTER_CS 0x174
// #define MSR_SYSENTER_ESP 0x175
// #define MSR_SYSENTER_EIP 0x176

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
#define write_dr0(value) write_dr(0, value)
#define write_dr1(value) write_dr(1, value)
#define write_dr2(value) write_dr(2, value)
#define write_dr3(value) write_dr(3, value)
#define write_dr6(value) write_dr(6, value)
#define write_dr7(value) write_dr(7, value)

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

// Figure 8-13. Long-Mode Interrupt Control Transfer
struct tptr {
	uint16_t	limit;         // segment limit
	uint64_t	base;          // base address
} __attribute__((packed));

#define IDTD_P                  (1 << 7)
#define IDTD_CPL3		        (3 << 5)
#define IDTD_TRAP_GATE          0xF
#define IDTD_INTERRUPT_GATE     0xE

#define IDT_ENTRIES     256

// Figure 4-24. Interrupt-Gate and Trap-Gate Descriptors—Long Mode
struct idtd {
        uint16_t        low;           // low 16 bits of handler address
        uint16_t        selector;      // kernel segment selector
        uint8_t         ist;           // bits 0..2 holds Interrupt Stack Table offset, rest of bits zero.
        uint8_t         type;          // type and attributes
        uint16_t        middle;        // middle 16 bits of handler address
        uint32_t        high;          // high 32 bits of handler address
        uint32_t        zero;          // reserved
} __attribute__((packed)) __attribute__ ((aligned));

// A.1 MSR Cross-Reference by MSR Address
#ifndef CROSS_REFERENCE_TABLE
// Table A-1. MSRs of the AMD64 Architecture
#define MSR_SYSENTER_CS   0x0174
#define MSR_SYSENTER_ESP  0x0175
#define MSR_SYSENTER_EIP  0x0176

#define MSR_U_CET   0x06A0
#define MSR_S_CET   0x06A2
#define MSR_PL0_SSP 0x06A4
#define MSR_PL1_SSP 0x06A5
#define MSR_PL2_SSP 0x06A6
#define MSR_PL3_SSP 0x06A7
#define MSR_ISST_ADDR 0x06A8
#define MSR_APIC_ID  0x802
#define MSR_APIC_EOI 0x80B
#define MSR_APIC_ICR 0x830
#define MSR_XSS     0x0DA0
#define MSR_EFER     0xC0000080
#define MSR_STAR     0xC0000081
#define MSR_LSTAR    0xC0000082
#define MSR_CSTAR    0xC0000083
#define MSR_SF_MASK  0xC0000084

#define MSR_FS_BASE        0xC0000100
#define MSR_GS_BASE        0xC0000101
#define MSR_KERNEL_GS_BASE 0xC0000102
#define MSR_TSC_AUX        0xC0000103

#define MSR_GHCB           0xC0010130
#define MSR_SEV_STATUS     0xC0010131
#define MSR_RMP_BASE       0xC0010132
#define MSR_RMP_END        0xC0010133
#define MSR_GUEST_TSC_FREQ 0xC0010134
#define MSR_VIRTUAL_TOM    0xC0010135

#define MSR_DR1_ADDR_MASK           0xC0011019
#define MSR_DR2_ADDR_MASK           0xC001101A
#define MSR_DR3_ADDR_MASK           0xC001101B
#define MSR_DR0_ADDR_MASK           0xC0011027
#define MSR_L3_RANGE_RESERVE_BASE   0xC0011095
#define MSR_L3_RANGE_RESERVE_MAX    0xC0011096
#define MSR_L3_RANGE_RESERVE_WAY    0xC001109A
#else
// Table A-2. System-Software MSR Cross-Reference
#define MSR_APIC_BASE       0x1B
#define MSR_EFER            0xC0000080
#define MSR_STAR            0xC0000081
#define MSR_LSTAR           0xC0000082
#define MSR_CSTAR           0xC0000083
#define MSR_SF_MASK         0xC0000084
#define MSR_FS_BASE         0xC0000100
#define MSR_GS_BASE         0xC0000101
#define MSR_KERNEL_GS_BASE  0xC0000102
#define MSR_TSC_AUX         0xC0000103
#define MSR_TSC_RATIO       0xC0000104
#define MSR_SYSENTER_CS     0x174
#define MSR_SYSENTER_ESP    0x175
#define MSR_SYSENTER_EIP    0x176

// Table A-5. Software-Debug MSR Cross-Reference
#define MSR_DEBUG_CTL           0x01D9
#define MSR_LAST_BRANCH_FROM_IP 0x01DB
#define MSR_LAST_BRANCH_TO_IP   0x01DC
#define MSR_LAST_INT_FROM_IP    0x01DD
#define MSR_LAST_INT_TO_IP      0x01DE
#define MSR_DR0_ADDR_MASK   0xC0001027
#define MSR_DR1_ADDR_MASK   0xC0001019
#define MSR_DR2_ADDR_MASK   0xC000101A
#define MSR_DR3_ADDR_MASK   0xC000101B

// Table A-7. Secure Virtual Machine MSR Cross-Reference
#define MSR_TSC_RATIO       0xC0000104
#define MSR_VM_CR           0xC0010114
#define MSR_IGNNE           0xC0010115
#define MSR_SMM_CTL         0xC0010116
#define MSR_VM_HSAVE_PA     0xC0010117
#define MSR_SVM_KEY         0xC0010118
#define MSR_DOORBELL        0xC001011B
#define MSR_VMPAGE_FLUSH    0xC001011E
#define MSR_GHCB            0xC0010130
#define MSR_SEV_STATUS      0xC0010131
#define MSR_RMP_BASE        0xC0010132
#define MSR_RMP_END         0xC0010133
#define MSR_GUEST_TSC_FREQ  0xC0010134

// Table A-8. System Management Mode MSR Cross-Reference
#define MSR_SMI_TRIGGER_IO_CYCLE    0xC0010056
#define MSR_PSTATE_CURRENT_LIMIT    0xC0010061
#define MSR_PSTATE_CONTROL          0xC0010062
#define MSR_PSTATE_STATUS           0xC0010063
#define MSR_SMBASE                  0xC0010111
#define MSR_SMM_ADDR                0xC0010112
#define MSR_SMM_MASK                0xC0010113
#define MSR_SMM_KEY_MSR             0xC0010119
#define MSR_LOCAL_SMI_STATUS        0xC001011A

// Table A-10. Shadow Stack MSR Cross Reference 
#define MSR_U_CET           0x06A0
#define MSR_S_CET           0x06A2
#define MSR_PL0_SSP         0x06A4
#define MSR_PL1_SSP         0x06A5
#define MSR_PL2_SSP         0x06A6
#define MSR_PL3_SSP         0x06A7
#define MSR_ISST_ADDR       0x06A8
#endif

// 8.2 Vectors
// Table 8-1. Interrupt Vector Source and Cause
#define T_DE 0 /* Divide Error Fault */
#define T_DB 1 /* Debug Trap or Fault */
#define T_NMI 2 /* Nonmaskable Interrupt */
#define T_BP 3 /* Breakpoint Trap */
#define T_OF 4 /* Overflow Trap */
#define T_BR 5 /* BOUND Range Exceeded Fault */
#define T_UD 6 /* Invalid Opcode Fault */
#define T_NM 7 /* Device Not Available Fault */
#define T_DF 8 /* Double Fault Abort */
#define T_TS 10 /* Invalid TSS Fault */
#define T_NP 11 /* Segment Not Present Fault */
#define T_SS 12 /* Stack Fault */
#define T_GP 13 /* General Protection Fault */
#define T_PF 14 /* Page Fault */
#define T_MF 16 /* x87 FPU Floating-Point Error Fault */
#define T_AC 17 /* Alignment Check Fault */
#define T_MC 18 /* Machine Check Abort */
#define T_XF 19 /* SIMD Floating-Point Exception Fault */
#define T_CP 21 /* Control Protection Exception Fault */
#define T_HV 28 /* Hypervisor Injection Exception Fault */
#define T_VC 29 /* VMM Communication Exception Fault */
#define T_SX 30 /* Security Exception Fault */

// These are arbitrarily chosen, but with care not to overlap
// processor defined exceptions or interrupt vectors.
#define T_SYSCALL   48		// system call

// Table 6-1. System Management Instructions



static inline void sgdt(void *addr) {
    __asm__ __volatile__("sgdt %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void lgdt(void *addr) {
    __asm__ __volatile__("lgdt %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void sidt(void *addr) {
    __asm__ __volatile__("sidt %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void lidt(void *addr) {
    __asm__ __volatile__("lidt %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void sldt(void *addr) {
    __asm__ __volatile__("sldt %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void lldt(void *addr) {
    __asm__ __volatile__("lldt %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void str(void *addr) {
    __asm__ __volatile__("str %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void ltr(void *addr) {
    __asm__ __volatile__("ltr %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void smsw(void *addr) {
    __asm__ __volatile__("smsw %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void lmsw(void *addr) {
    __asm__ __volatile__("lmsw %0"
                         :
                         : "m"(*(struct tptr *)addr)
                         : "memory");
}

static inline void swapgs(void) {
    __asm__ __volatile__("swapgs"
                         :
                         :
                         : "memory");
}

static inline void wbinvd(void) {
    __asm__ __volatile__("wbinvd"
                         :
                         :
                         : "memory");
}

static inline void wbnoinvd(void) {
    __asm__ __volatile__("wbnoinvd"
                         :
                         :
                         : "memory");
}

static inline uint64_t rdfsbase(void) {
    uint64_t value;
    __asm__ __volatile__("rdfsbase %0"
                         : "=r"(value)
                         :
                         : "memory");
    return value;
}

static inline void wrfsbase(void *addr) {
    __asm__ __volatile__("wrfsbase %0"
                         :
                         : "r"(addr)
                         : "memory");
}

static inline uint64_t rdgsbase(void) {
    uint64_t value;
    __asm__ __volatile__("rdgsbase %0"
                         : "=r"(value)
                         :
                         : "memory");
    return value;
}

static inline void wrgsbase(void *addr) {
    __asm__ __volatile__("wrgsbase %0"
                         :
                         : "r"(addr)
                         : "memory");
}

// Memory Protection Keys

static inline uint32_t rdpkru(void) {
    uint32_t value;
    __asm__ __volatile__("rdpkru %0"
                         : "=r"(value)
                         :
                         : "memory");
    return value;
}

static inline void wrpkru(uint32_t pkru) {
    __asm__ __volatile__("wrpkru %0"
                         :
                         : "r"(pkru)
                         : "memory");
}

// Shadow Stack Instructions

static inline void clrssbsy(void) {
    __asm__ __volatile__("clrssbsy"
                         :
                         :
                         : "memory");
}

static inline void incssp(void) {
    __asm__ __volatile__("incssp"
                         :
                         :
                         : "memory");
}

static inline uint64_t rdssp(void) {
    uint64_t value;
    __asm__ __volatile__("rdssp %0"
                         : "=r"(value)
                         :
                         : "memory");
    return value;
}

static inline void setssbsy(void) {
    __asm__ __volatile__("setssbsy"
                         :
                         :
                         : "memory");
}

static inline void wrss(void *addr) {
    __asm__ __volatile__("wrss %0"
                         :
                         : "r"(addr)
                         : "memory");
}

static inline void wruss(void *addr) {
    __asm__ __volatile__("wruss %0"
                         :
                         : "r"(addr)
                         : "memory");
}

// Control Registers

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

#define read_rflags() ({ \
    uint64_t value; \
    asm volatile("pushfq; popq %0" : "=r"(value) : : "memory"); \
    value; \
})

#define test_rflags(mask) ({ \
    uint64_t value; \
    asm volatile("pushfq; popq %0" : "=r"(value) : : "memory"); \
    (value & (mask)) == (mask); \
})

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

#define rdmsrl(msr, val) ((val) = rdmsr(msr))

// Write to MSR a given value
static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t lo = (uint32_t)value;
    uint32_t hi = (uint32_t)(value >> 32);

    __asm__ __volatile__("wrmsr"
                         :
                         : "c"(msr), "a"(lo), "d"(hi)
                         : "memory");
}

#define wrmsrl(msr, val) wrmsr(msr, val)

static inline unsigned long rdtsc(void) {
    unsigned long lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (hi << 32) | lo;
}

static inline unsigned long rdtscp(void) {
    unsigned long lo, hi;
    __asm__ __volatile__("rdtscp" : "=a"(lo), "=d"(hi));
    return (hi << 32) | lo;
}

// Pause instruction
#ifndef __x86_64__
static inline int pause() {
    __asm__("pause");
    return 0;
}
#endif

static inline void clac(void) {
    __asm__ __volatile__("clac"
                         :
                         :
                         : "memory");
}

static inline void stac(void) {
    __asm__ __volatile__("stac"
                         :
                         :
                         : "memory");
}

static inline void clgi(void) {
    __asm__ __volatile__("clgi"
                         :
                         :
                         : "memory");
}

static inline void stgi(void) {
    __asm__ __volatile__("stgi"
                         :
                         :
                         : "memory");
}

static inline void cli(void) {
    __asm__ __volatile__("cli"
                         :
                         :
                         : "memory");
}

static inline void sti(void) {
    __asm__ __volatile__("sti"
                         :
                         :
                         : "memory");
}

// Halt instruction
static inline void halt() {
    __asm__("hlt");
}

static inline void int3() {
    __asm__("int3");
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
static inline uint32_t pvalidate(uint64_t va, uint32_t page_size, uint32_t validation) {
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

static inline void invd(void) {
    __asm__ __volatile__("invd"
                         :
                         :
                         : "memory");
}

static inline void invlpg(void *addr) {
    __asm__ __volatile__("invlpg (%0)"
                         :
                         : "r"(addr)
                         : "memory");
}

static inline void invlpga(void *addr, uint64_t asid) {
    __asm__ __volatile__("invlpga %0, %1"
                         :
                         : "r"(addr), "r"(asid)
                         : "memory");
}

// Flush everything for the ASID, including Global entries
static inline void invlpgb_all(void) {
    uint32_t rax = BIT(3);

    __asm__ __volatile__(".byte 0x0f,0x01,0xfe"
                         :
                         : "a"(rax), "c"(0), "d"(0)
                         : "memory");
}

static inline void invlpgb(void *addr, uint64_t asid) {
    __asm__ __volatile__("invlpgb %0, %1"
                         :
                         : "r"(addr), "r"(asid)
                         : "memory");
}

static inline void invpcid(void) {
    uint32_t rax = BIT(3);

    __asm__ __volatile__(".byte 0x66,0x0f,0x38,0x82"
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

// Flush a single TLB entry
static inline void flush_tlb_one(unsigned long addr)
{
	asm("invlpg (%0)" ::"r"(addr) : "memory");
}

// Flush the entire TLB
static inline void flush_tlb(void)
{
	asm("mov %%cr3, %%rax\n"
		"mov %%rax, %%cr3\n" ::
			: "rax");
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