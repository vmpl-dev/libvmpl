#include <stddef.h>
#include <stdint.h>

struct VmsaSegmentRegister {
    uint16_t selector;
    uint16_t rtype;
    uint32_t limit;
    uint64_t base;
};

struct Vmsa {
    struct VmsaSegmentRegister es;
    struct VmsaSegmentRegister cs;
    struct VmsaSegmentRegister ss;
    struct VmsaSegmentRegister ds;
    struct VmsaSegmentRegister fs;
    struct VmsaSegmentRegister gs;
    struct VmsaSegmentRegister gdtr;
    struct VmsaSegmentRegister ldtr;
    struct VmsaSegmentRegister idtr;
    struct VmsaSegmentRegister tr;

    uint8_t reserved1[42];

    uint8_t vmpl;
    uint8_t cpl;

    uint8_t reserved2[4];

    uint64_t efer;

    uint8_t reserved3[104];

    uint64_t xss;
    uint64_t cr4;
    uint64_t cr3;
    uint64_t cr0;
    uint64_t dr7;
    uint64_t dr6;
    uint64_t rflags;
    uint64_t rip;

    uint8_t reserved4[88];

    uint64_t rsp;

    uint8_t reserved5[24];

    uint64_t rax;

    uint8_t reserved6[104];

    uint64_t gpat;

    uint8_t reserved7[124];
    uint32_t tsc_aux;
    uint64_t tsc_scale;
    uint64_t tsc_offset;
    uint8_t reserved_0x300[8];
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;

    uint8_t reserved8[8];

    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;

    uint8_t reserved9[48];

    uint64_t sev_features;

    uint8_t reserved10[8];

    uint64_t guest_exitcode;

    uint64_t virtual_tom;

    uint8_t reserved11[24];

    uint64_t xcr0;

    uint8_t reserved12[16];

    uint64_t x87_dp;
    uint32_t mxcsr;
    uint16_t x87_ftw;
    uint16_t x87_fsw;
    uint16_t x87_fcw;
    uint16_t x87_fop;
    uint16_t x87_ds;
    uint16_t x87_cs;
    uint64_t x87_rip;
    uint8_t fpreg_x87[80];
    uint8_t fpreg_xmm[256];
    uint8_t fpreg_ymm[256];

    uint8_t reserved13[2448];
};

struct Ca {
    uint8_t call_pending;
    uint8_t mem_available;
    uint8_t reserved1[6];
    uint8_t shared_mem[4088];
};

#define PAGE_SIZE 4096

_Static_assert(sizeof(struct Vmsa) == PAGE_SIZE, "Vmsa size is not equal to PAGE_SIZE");
_Static_assert(sizeof(struct Ca) == PAGE_SIZE, "Ca size is not equal to PAGE_SIZE");