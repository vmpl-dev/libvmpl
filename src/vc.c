#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#ifdef __GLIBC__
#include <asm/msr.h>
#else
#include <bits/syscall.h>
#endif
#include "config.h"
#include "sys.h"
// #include "syscall.h"
#include "mm.h"
#include "log.h"
#include "vc.h"

static uint64_t HV_FEATURES;
static __thread Ghcb* this_ghcb = NULL;

void vc_terminate(uint64_t reason_set, uint64_t reason_code) {
    uint64_t value;

    wrmsrl(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_VMPL_REQ_LEVEL(RUN_VMPL));

    value = GHCB_MSR_TERMINATE_REQ;
    value |= reason_set << 12;
    value |= reason_code << 16;

	syscall(__NR_exit, value);
}

static inline void vc_terminate_vmpl_general() {
    vc_terminate(VMPL_REASON_CODE_SET, VMPL_TERM_GENERAL);
}

static inline void vc_terminate_vmpl_enomem() {
    vc_terminate(VMPL_REASON_CODE_SET, VMPL_TERM_ENOMEM);
}

static inline void vc_terminate_vmpl_resp_invalid() {
    vc_terminate(VMPL_REASON_CODE_SET, VMPL_TERM_GHCB_RESP_INVALID);
}

static inline void vc_terminate_vmpl_page_err() {
    vc_terminate(VMPL_REASON_CODE_SET, VMPL_TERM_SET_PAGE_ERROR);
}

static inline void vc_terminate_vmpl_psc() {
    vc_terminate(VMPL_REASON_CODE_SET, VMPL_TERM_PSC_ERROR);
}

static inline void vc_terminate_unhandled_vc() {
    vc_terminate(VMPL_REASON_CODE_SET, VMPL_TERM_UNHANDLED_VC);
}

static inline void vc_terminate_ghcb_general() {
    vc_terminate(GHCB_REASON_CODE_SET, GHCB_TERM_GENERAL);
}

static inline void vc_terminate_ghcb_unsupported_protocol() {
    vc_terminate(GHCB_REASON_CODE_SET, GHCB_TERM_UNSUPPORTED_PROTOCOL);
}

static inline void vc_terminate_ghcb_feature() {
    vc_terminate(GHCB_REASON_CODE_SET, GHCB_TERM_FEATURE_SUPPORT);
}

static inline void vc_terminate_vmpl1_sev_features() {
    vc_terminate(VMPL_REASON_CODE_SET, VMPL_TERM_VMPL1_SEV_FEATURES);
}

static inline void vc_terminate_vmpl0_sev_features() {
    vc_terminate(VMPL_REASON_CODE_SET, VMPL_TERM_VMPL0_SEV_FEATURES);
}

void vc_handler(uint64_t rip, uint64_t error_code, uint64_t cr2, uint64_t stack[5]) {
    printf("Unhandled #VC exception: %lx\n", error_code);
#ifdef CONFIG_STACK_TRACE
    print_stack(stack);
#endif
    printf("RIP=%lx, CR2=%lx\n", rip, cr2);
    vc_terminate_unhandled_vc();
}

static inline uint64_t vc_msr_protocol(uint64_t request)
{
    uint64_t response, value;

    // Save the current GHCB MSR value
    rdmsrl(MSR_AMD64_SEV_ES_GHCB, value);

    // Perform the MSR protocol
    wrmsrl(MSR_AMD64_SEV_ES_GHCB, request);
    vc_vmgexit();
    rdmsrl(MSR_AMD64_SEV_ES_GHCB, response);

    // Restore the GHCB MSR value
    wrmsrl(MSR_AMD64_SEV_ES_GHCB, value);

    return response;
}

uint64_t vc_establish_protocol() {
    uint64_t response;

    // Request SEV information
    response = vc_msr_protocol(GHCB_MSR_SEV_INFO_REQ);

    // Validate the GHCB protocol version
    if (GHCB_MSR_INFO(response) != GHCB_MSR_SEV_INFO_RES) {
        vc_terminate_ghcb_general();
    }

    if (GHCB_MSR_PROTOCOL_MIN(response) > GHCB_PROTOCOL_MAX
        || GHCB_MSR_PROTOCOL_MAX(response) < GHCB_PROTOCOL_MIN) {
        vc_terminate_ghcb_unsupported_protocol();
    }

    // Request hypervisor feature support
    response = vc_msr_protocol(GHCB_MSR_HV_FEATURE_REQ);

    // Validate required SVSM feature(s)
    if (GHCB_MSR_INFO(response) != GHCB_MSR_HV_FEATURE_RES) {
        vc_terminate_ghcb_general();
    }

    if ((GHCB_MSR_HV_FEATURES(response) & GHCB_SVSM_FEATURES) != GHCB_SVSM_FEATURES) {
        vc_terminate_ghcb_feature();
    }

    HV_FEATURES = GHCB_MSR_HV_FEATURES(response);

    return response;
}

Ghcb *get_early_ghcb() {
    return this_ghcb;
}

Ghcb* vc_get_ghcb()
{
    Ghcb* ghcb = this_ghcb;
    if (ghcb == NULL) {
        ghcb = (Ghcb*)pgtable_pa_to_va((PhysAddr)rdmsr(MSR_AMD64_SEV_ES_GHCB));
        this_ghcb = ghcb;
    }

    return ghcb;
}

void vc_set_ghcb(Ghcb *ghcb) {
    this_ghcb = ghcb;
}

void vc_perform_vmgexit(Ghcb* ghcb, uint64_t code, uint64_t info1, uint64_t info2) {
    ghcb_set_version(ghcb, GHCB_VERSION_1);
    ghcb_set_usage(ghcb, GHCB_USAGE);

    ghcb_set_sw_exit_code(ghcb, code);
    ghcb_set_sw_exit_info_1(ghcb, info1);
    ghcb_set_sw_exit_info_2(ghcb, info2);

    vc_vmgexit();

    if (!ghcb_is_sw_exit_info_1_valid(ghcb)) {
        vc_terminate_vmpl_resp_invalid();
    }

    uint64_t info1_new = ghcb_get_sw_exit_info_1(ghcb);
    if (LOWER_32BITS(info1_new) != 0) {
        vc_terminate_ghcb_general();
    }
}

void vc_run_vmpl(VMPL vmpl) {
    Ghcb* ghcb = vc_get_ghcb();

    vc_perform_vmgexit(ghcb, GHCB_NAE_RUN_VMPL, (uint64_t)vmpl, 0);

    ghcb_clear(ghcb);
}

static void vc_cpuid_vmgexit(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    Ghcb* ghcb = vc_get_ghcb();

    ghcb_set_rax(ghcb, leaf);
    ghcb_set_rcx(ghcb, subleaf);
    if (leaf == CPUID_EXTENDED_STATE) {
        if (read_xcr0() & 0x6) {
            ghcb_set_xcr0(ghcb, read_xcr0());
        } else {
            ghcb_set_xcr0(ghcb, 1);
        }
    }

    vc_perform_vmgexit(ghcb, GHCB_NAE_CPUID, 0, 0);

    if (!ghcb_is_rax_valid(ghcb) 
        || !ghcb_is_rbx_valid(ghcb)
        || !ghcb_is_rcx_valid(ghcb)
        || !ghcb_is_rdx_valid(ghcb)) {
        vc_terminate_vmpl_resp_invalid();
    }

    *eax = ghcb_get_rax(ghcb);
    *ebx = ghcb_get_rbx(ghcb);
    *ecx = ghcb_get_rcx(ghcb);
    *edx = ghcb_get_rdx(ghcb);

    ghcb_clear(ghcb);
}

void vc_outl(uint16_t port, uint32_t value) {
    Ghcb* ghcb = vc_get_ghcb();

    uint64_t ioio = ((uint64_t)port) << 16;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_32;

    ghcb_set_rax(ghcb, value);

    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

    ghcb_clear(ghcb);
}

uint32_t vc_inl(uint16_t port) {
    Ghcb* ghcb = vc_get_ghcb();

    uint64_t ioio = ((uint64_t)port) << 16;
    uint32_t value;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_32;
    ioio |= IOIO_TYPE_IN;

    ghcb_set_rax(ghcb, 0);

    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

    if (!ghcb_is_rax_valid(ghcb)) {
        vc_terminate_vmpl_resp_invalid();
    }

    value = (uint32_t)(LOWER_32BITS(ghcb_get_rax(ghcb)));

    ghcb_clear(ghcb);

    return value;
}

void vc_outw(uint16_t port, uint16_t value) {
    Ghcb* ghcb = vc_get_ghcb();
    uint64_t ioio = ((uint64_t)port) << 16;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_16;

    ghcb_set_rax(ghcb, value);

    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

    ghcb_clear(ghcb);
}

uint16_t vc_inw(uint16_t port) {
    Ghcb* ghcb = vc_get_ghcb();
    uint64_t ioio = ((uint64_t)port) << 16;
    uint16_t value;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_16;
    ioio |= IOIO_TYPE_IN;

    ghcb_set_rax(ghcb, 0);

    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

    if (!ghcb_is_rax_valid(ghcb)) {
        vc_terminate_vmpl_resp_invalid();
    }

    value = (uint16_t)LOWER_16BITS(ghcb_get_rax(ghcb));

    ghcb_clear(ghcb);

    return value;
}

void vc_outb(uint16_t port, uint8_t value) {
    Ghcb* ghcb = vc_get_ghcb();
    uint64_t ioio = ((uint64_t)port) << 16;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_8;

    ghcb_set_rax(ghcb, value);

    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

    ghcb_clear(ghcb);
}

uint8_t vc_inb(uint16_t port) {
    Ghcb* ghcb = vc_get_ghcb();
    uint64_t ioio = ((uint64_t)port) << 16;
    uint8_t value;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_8;
    ioio |= IOIO_TYPE_IN;

    ghcb_set_rax(ghcb, 0);

    vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);


    if (!ghcb_is_rax_valid(ghcb)) {
        vc_terminate_vmpl_resp_invalid();
    }

    value = (uint8_t)LOWER_8BITS(ghcb_get_rax(ghcb));

    ghcb_clear(ghcb);

    return value;
}

// 0x012 - Register GHCB GPA Request
void vc_register_ghcb(PhysAddr pa) {
    // Perform GHCB registration
    uint64_t response = vc_msr_protocol(GHCB_MSR_REGISTER_GHCB(pa));

    // Validate the response
    if (GHCB_MSR_INFO(response) != GHCB_MSR_REGISTER_GHCB_RES) {
        vc_terminate_vmpl_general();
    }

    if (GHCB_MSR_DATA(response) != pa) {
        vc_terminate_vmpl_general();
    }

    wrmsrl(MSR_AMD64_SEV_ES_GHCB, pa);
}

#ifdef CONFIG_VMPL_MSR_PROTOCOL
// 0x014 - SNP Page State Change Request
void vc_snp_page_state_change(PhysAddr pa, uint64_t op) {
    // Perform SNP page state change
    uint64_t response = vc_msr_protocol(GHCB_MSR_SNP_PSC(pa, op));

    // Validate the response
    if (GHCB_MSR_INFO(response) != GHCB_MSR_SNP_PSC_RES) {
        vc_terminate_vmpl_general();
    }

    if (GHCB_MSR_SNP_PSC_VAL(response) != pa) {
        vc_terminate_vmpl_general();
    }
}

void vc_make_page_private(PhysAddr pa) {
    vc_snp_page_state_change(pa, SNP_PSC_OP_ASSIGN_PRIVATE);
}

void vc_make_page_shared(PhysAddr pa) {
    vc_snp_page_state_change(pa, SNP_PSC_OP_ASSIGN_SHARED);
}
#endif

#define PSC_SHARED (2ull << 52)
#define PSC_PRIVATE (1ull << 52)
#define PSC_ENTRIES ((SHARED_BUFFER_SIZE - sizeof(PscOpHeader)) / 8)

typedef struct {
    uint16_t cur_entry;
    uint16_t end_entry;
    uint32_t reserved;
} PscOpHeader;

typedef struct {
    uint64_t data;
} PscOpData;

typedef struct {
    PscOpHeader header;
    PscOpData entries[PSC_ENTRIES];
} PscOp;

#define GHCB_2MB_PSC_ENTRY(x, y) (((x) | (y) | (1ull << 56)) & UINT64_MAX)
#define GHCB_4KB_PSC_ENTRY(x, y) (((x) | (y)) & UINT64_MAX)
#define GHCB_PSC_GPA(x) (((x) & ((1ull << 52) - 1)) & UINT64_MAX)
#define GHCB_PSC_SIZE(x) ((((x) >> 56) & 1) & UINT32_MAX)

void pvalidate_psc_entries(PscOp* op, uint32_t pvalidate_op) {
    size_t first_entry = (size_t)op->header.cur_entry;
    size_t last_entry = (size_t)op->header.end_entry + 1;

    for (size_t i = first_entry; i < last_entry; i++) {
        uint64_t gpa = GHCB_PSC_GPA(op->entries[i].data);
        uint32_t size = GHCB_PSC_SIZE(op->entries[i].data);

        VirtAddr va = pgtable_pa_to_va((PhysAddr)gpa);
        uint32_t ret = pvalidate(va, size, pvalidate_op);
        if (ret == PVALIDATE_FAIL_SIZE_MISMATCH && size > 0) {
            VirtAddr va_end = va + PAGE_2MB_SIZE;

            while (va < va_end) {
                ret = pvalidate(va, 0, pvalidate_op);
                if (ret != 0) {
                    break;
                }

                va += PAGE_SIZE;
            }
        }

        if (ret != 0) {
            vc_terminate_vmpl_psc();
        }
    }
}

void build_psc_entries(PscOp* op, PhysAddr begin, PhysAddr end, uint64_t page_op) {
    PhysAddr pa = begin;
    size_t i = 0;

    while (pa < end && i < PSC_ENTRIES) {
        if (is_aligned(pa, PAGE_2MB_SIZE) && (end - pa) >= PAGE_2MB_SIZE) {
            op->entries[i].data = GHCB_2MB_PSC_ENTRY(pa, page_op);
            pa += PAGE_2MB_SIZE;
        } else {
            op->entries[i].data = GHCB_4KB_PSC_ENTRY(pa, page_op);
            pa += PAGE_SIZE;
        }
        op->header.end_entry = (uint16_t)i;

        i++;
    }
}

void perform_page_state_change(Ghcb* ghcb, PhysFrame begin, PhysFrame end, uint64_t page_op) {
    PscOp op;

    PhysAddr pa = begin << PAGE_SHIFT;
    PhysAddr pa_end = end << PAGE_SHIFT;

    while (pa < pa_end) {
        op.header.cur_entry = 0;
        build_psc_entries(&op, pa, pa_end, page_op);

        uint16_t last_entry = op.header.end_entry;

        if (page_op == PSC_SHARED) {
            pvalidate_psc_entries(&op, RESCIND);
        }

        size_t size = sizeof(PscOpHeader) + sizeof(PscOpData) * (last_entry + 1);
        void* set_bytes = &op;
        void* get_bytes = &op;

        ghcb_clear(ghcb);
        ghcb_set_shared_buffer(ghcb, set_bytes, size);

        while (op.header.cur_entry <= last_entry) {
            vc_perform_vmgexit(ghcb, GHCB_NAE_PSC, 0, 0);
            if (!ghcb_is_sw_exit_info_2_valid(ghcb) || ghcb_get_sw_exit_info_2(ghcb) != 0) {
                vc_terminate_vmpl_psc();
            }

            ghcb_get_shared_buffer(ghcb, get_bytes, size);
        }

        if (page_op == PSC_PRIVATE) {
            op.header.cur_entry = 0;
            op.header.end_entry = last_entry;
            pvalidate_psc_entries(&op, VALIDATE);
        }
    }
}

void vc_make_pages_shared(PhysFrame begin, PhysFrame end) {
    Ghcb* ghcb = vc_get_ghcb();
    perform_page_state_change(ghcb, begin, end, PSC_SHARED);
}

#ifndef CONFIG_VMPL_MSR_PROTOCOL
void vc_make_page_shared(PhysFrame frame) {
    vc_make_pages_shared(frame, frame + 1);
}
#endif

void vc_make_pages_private(PhysFrame begin, PhysFrame end) {
    Ghcb* ghcb = vc_get_ghcb();
    perform_page_state_change(ghcb, begin, end, PSC_PRIVATE);
}

#ifndef CONFIG_VMPL_MSR_PROTOCOL
void vc_make_page_private(PhysFrame frame) {
    vc_make_pages_private(frame, frame + 1);
}
#endif

void vc_early_make_pages_private(PhysFrame begin, PhysFrame end) {
    Ghcb* ghcb = (Ghcb*)get_early_ghcb();
    perform_page_state_change(ghcb, begin, end, PSC_PRIVATE);
}

#ifdef CONFIG_VMPL_GHCB
void vc_init(Ghcb *ghcb_va) {
	PhysAddr ghcb_pa;
	log_info("setup VC");

	ghcb_pa = (PhysAddr)pgtable_va_to_pa((VirtAddr)ghcb_va);
    log_debug("ghcb_pa: %lx", ghcb_pa);

    vc_establish_protocol();
    vc_register_ghcb(ghcb_pa);
    vc_set_ghcb(ghcb_va);
}
#endif