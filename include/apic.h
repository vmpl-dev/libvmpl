#ifndef APIC_H
#define APIC_H

#include <stdbool.h>
#include <stdint.h>

uint32_t apic_get_id();
int apic_setup();
void apic_cleanup();
void apic_init_rt_entry();
uint32_t apic_get_id_for_cpu(uint32_t cpu, bool *error);
void apic_send_ipi(uint8_t vector, uint32_t dest_apic_id);
void apic_eoi();

#endif /* APIC_H */