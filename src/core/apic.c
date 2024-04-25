#define _GNU_SOURCE
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sched.h>
#include <sys/sysinfo.h>

#include "sys.h"
#include "log.h"
#include "vmpl.h"

#define APIC_DM_FIXED       0x00000
#define NMI_VECTOR          0x02
#define APIC_DM_NMI         0x00400
#define APIC_DEST_PHYSICAL  0x00000
#define EOI_ACK             0x0

static int *apic_routing;
static int num_rt_entries;

uint32_t apic_get_id()
{
    long long apic_id;
    rdmsrl(MSR_APIC_ID, apic_id);
    return (uint32_t)apic_id;
}

int apic_setup()
{
    log_info("setup apic");
    num_rt_entries = get_nprocs_conf();

    log_debug("num rt entries: %d", num_rt_entries);
    apic_routing = malloc(num_rt_entries * sizeof(int));

    if (!apic_routing) {
		log_err("apic routing table allocation failed");
		return -ENOMEM;
	}

    num_rt_entries = get_nprocs_conf();
    memset(apic_routing, -1, num_rt_entries * sizeof(int));
    asm("mfence" ::: "memory");
    
    return 0;
}

void apic_cleanup()
{
    free(apic_routing);
}

void apic_init_rt_entry()
{
    int core_id = sched_getcpu();
    apic_routing[core_id] = apic_get_id();
    asm("mfence" ::: "memory");
}

uint32_t apic_get_id_for_cpu(uint32_t cpu, bool *error)
{
    if (cpu >= num_rt_entries) {
        if (error) *error = true;
        return 0;
    }
    return apic_routing[cpu];
}

static inline unsigned int __prepare_ICR(unsigned int shortcut, int vector, unsigned int dest)
{
    unsigned int icr = shortcut | dest;
    switch (vector) {
    default:
        icr |= APIC_DM_FIXED | vector;
        break;
    case NMI_VECTOR:
        icr |= APIC_DM_NMI;
        break;
    }
    return icr;
}

void apic_send_ipi(uint8_t vector, uint32_t dest_apic_id)
{
    uint32_t low = __prepare_ICR(0, vector, APIC_DEST_PHYSICAL);
    wrmsrl(MSR_APIC_ICR, (((uint64_t)dest_apic_id) << 32) | low);
}

void apic_eoi()
{
    wrmsrl(MSR_APIC_EOI, EOI_ACK);
}