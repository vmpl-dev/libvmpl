#include <asm/msr.h>

#include "vc.h"

static uint64_t HV_FEATURES;

void vc_terminate(uint64_t reason_set, uint64_t reason_code) {
    uint64_t value;

    value = GHCB_MSR_TERMINATE_REQ;
    value |= reason_set << 12;
    value |= reason_code << 16;

    wrmsr(MSR_AMD64_SEV_ES_GHCB, value);
    vc_vmgexit();

    while (1) {
        halt();
    }
}

inline void vc_terminate_svsm_general() {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_GENERAL);
}

inline void vc_terminate_svsm_resp_invalid() {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_GHCB_RESP_INVALID);
}

inline void vc_terminate_unhandled_vc() {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_UNHANDLED_VC);
}

inline void vc_terminate_ghcb_general() {
    vc_terminate(GHCB_REASON_CODE_SET, GHCB_TERM_GENERAL);
}

inline void vc_terminate_ghcb_unsupported_protocol() {
    vc_terminate(GHCB_REASON_CODE_SET, GHCB_TERM_UNSUPPORTED_PROTOCOL);
}

inline void vc_terminate_ghcb_feature() {
    vc_terminate(GHCB_REASON_CODE_SET, GHCB_TERM_FEATURE_SUPPORT);
}

uint64_t vc_msr_protocol(uint64_t request) {
    uint64_t response;

    // Save the current GHCB MSR value
    uint64_t value = rdmsr(MSR_AMD64_SEV_ES_GHCB);

    // Perform the MSR protocol
    wrmsr(MSR_AMD64_SEV_ES_GHCB, request);
    vc_vmgexit();
    response = rdmsr(MSR_AMD64_SEV_ES_GHCB);

    // Restore the GHCB MSR value
    wrmsr(MSR_AMD64_SEV_ES_GHCB, value);

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

Ghcb* vc_get_ghcb() {
    // TODO: map ghcb into virtual address
    uint64_t ghcb_gpa = sev_es_rd_ghcb_msr();
}

void vc_perform_vmgexit(Ghcb* ghcb, uint64_t code, uint64_t info1, uint64_t info2) {
    ghcb_set_version(ghcb, GHCB_VERSION_1);
    ghcb_set_usage(ghcb, GHCB_USAGE);

    ghcb_set_sw_exit_code(ghcb, code);
    ghcb_set_sw_exit_info_1(ghcb, info1);
    ghcb_set_sw_exit_info_2(ghcb, info2);

    vc_vmgexit();

    if (!ghcb_is_sw_exit_info_1_valid(ghcb)) {
        vc_terminate_svsm_resp_invalid();
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
        vc_terminate_svsm_resp_invalid();
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
        vc_terminate_svsm_resp_invalid();
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
        vc_terminate_svsm_resp_invalid();
    }

    value = (uint8_t)LOWER_8BITS(ghcb_get_rax(ghcb));

    ghcb_clear(ghcb);

    return value;
}

void vc_register_ghcb(uint64_t pa) {
    // Perform GHCB registration
    uint64_t response = vc_msr_protocol(GHCB_MSR_REGISTER_GHCB(pa));

    // Validate the response
    if (GHCB_MSR_INFO(response) != GHCB_MSR_REGISTER_GHCB_RES) {
        vc_terminate_svsm_general();
    }

    if (GHCB_MSR_DATA(response) != pa) {
        vc_terminate_svsm_general();
    }

    wrmsr(MSR_AMD64_SEV_ES_GHCB, pa);
}

#ifdef PAGE_TABLE
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
        uint32_t ret = pvalidate(va.as_u64(), size, pvalidate_op);
        if (ret == PVALIDATE_FAIL_SIZE_MISMATCH && size > 0) {
            VirtAddr va_end = va + PAGE_2MB_SIZE;

            while (va < va_end) {
                ret = pvalidate(va.as_u64(), 0, pvalidate_op);
                if (ret != 0) {
                    break;
                }

                va += PAGE_SIZE;
            }
        }

        if (ret != 0) {
            vc_terminate_svsm_psc();
        }
    }
}

void build_psc_entries(PscOp* op, PhysAddr begin, PhysAddr end, uint64_t page_op) {
    PhysAddr pa = begin;
    size_t i = 0;

    while (pa < end && i < PSC_ENTRIES) {
        if (pa.is_aligned(PAGE_2MB_SIZE) && (end - pa) >= PAGE_2MB_SIZE) {
            op->entries[i].data = GHCB_2MB_PSC_ENTRY(pa.as_u64(), page_op);
            pa += PAGE_2MB_SIZE;
        } else {
            op->entries[i].data = GHCB_4KB_PSC_ENTRY(pa.as_u64(), page_op);
            pa += PAGE_SIZE;
        }
        op->header.end_entry = (uint16_t)i;

        i++;
    }
}

void perform_page_state_change(Ghcb* ghcb, PhysFrame begin, PhysFrame end, uint64_t page_op) {
    PscOp op;

    PhysAddr pa = begin.start_address();
    PhysAddr pa_end = end.start_address();

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

        ghcb->clear();
        ghcb->set_shared_buffer(set_bytes, size);

        while (op.header.cur_entry <= last_entry) {
            vc_perform_vmgexit(ghcb, GHCB_NAE_PSC, 0, 0);
            if (!ghcb->is_sw_exit_info_2_valid() || ghcb->sw_exit_info_2() != 0) {
                vc_terminate_svsm_psc();
            }

            ghcb->shared_buffer(get_bytes, size);
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

void vc_make_page_shared(PhysFrame frame) {
    vc_make_pages_shared(frame, frame + 1);
}

void vc_make_pages_private(PhysFrame begin, PhysFrame end) {
    Ghcb* ghcb = vc_get_ghcb();
    perform_page_state_change(ghcb, begin, end, PSC_PRIVATE);
}

void vc_make_page_private(PhysFrame frame) {
    vc_make_pages_private(frame, frame + 1);
}

void vc_early_make_pages_private(PhysFrame begin, PhysFrame end) {
    Ghcb* ghcb = (Ghcb*)get_early_ghcb();
    perform_page_state_change(ghcb, begin, end, PSC_PRIVATE);
}

#endif

// TODO: implement pgtable_va_to_pa, pgtable_va_to_pa
void vc_init() {
    // uint64_t ghcb_pa = (uint64_t)pgtable_va_to_pa(get_early_ghcb());

    // vc_establish_protocol();
    // vc_register_ghcb(ghcb_pa);
}