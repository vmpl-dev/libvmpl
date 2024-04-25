#include "mm.h"
#include "idt.h"
#include "vmpl.h"
#include "log.h"

struct idtd idt[IDT_ENTRIES];

static inline void __set_idt_addr(struct idtd *id, phys_addr_t addr)
{
    id->low    = addr & 0xFFFF;
    id->middle = (addr >> 16) & 0xFFFF;
    id->high   = (addr >> 32) & 0xFFFFFFFF;
}

static inline void __init_idtd(struct idtd *id, int i, uintptr_t isr)
{
    memset(id, 0, sizeof(*id));
    id->selector = GD_KT;
    id->type     = IDTD_P | IDTD_TRAP_GATE;
    switch (i) {
    case T_BP:
        id->type |= IDTD_CPL3;
        /* fallthrough */
    case T_DF:
    case T_NMI:
    case T_MC:
        id->ist = 1;
        break;
    }
    __set_idt_addr(id, isr);
}

void dump_idt(struct idtd *idt)
{
    log_debug("IDT Entries:");
    for (int i = 0; i < IDT_ENTRIES; i++)
    {
        struct idtd *id = &idt[i];
        log_debug("IDT Entry[%d]: %016lx", i, idt[i]);
        log_debug(" IST: %02x Type: %02x Addr: %08x%04x%04x", id->ist, id->type, id->high, id->middle, id->low);
    }
}

void setup_idt(void)
{
    uintptr_t isr = (uintptr_t) &__dune_intr;
    log_info("setup idt");

	for (size_t i = 0; i < IDT_ENTRIES; i++) {
        __init_idtd(&idt[i], i, isr + ISR_LEN * i);
	}
}