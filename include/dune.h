#ifndef __DUNE_H_
#define __DUNE_H_

#include "vmpl.h"
#include "apic.h"
#include "mm.h"

#define ptent_t             pte_t
#define PTE_ADDR            pte_addr
#define load_cr3            pgtable_load_cr3
#define dune_flush_tlb      flush_tlb
#define dune_flush_tlb_one  flush_tlb_one
#define dune_printf         printf
#define dune_puts           puts
#define dune_mmap           mmap
#define dune_die            exit
#define dune_get_ticks      rdtsc

#define dune_fd             vmpl_fd

#define dune_enter()          vmpl_enter(1, NULL)
#define dune_init_and_enter() vmpl_enter(1, NULL)

#define dune_apic_ipi       apic_send_ipi
#define dune_apic_eoi       apic_eoi
#define dune_apic_init_rt_entry apic_init_rt_entry
#define dune_apic_id_for_cpu    apic_get_id_for_cpu
#define dune_apic_send_ipi      apic_send_ipi

#define dune_va_to_pa       pgtable_va_to_pa
#define dune_vm_mprotect	vmpl_vm_mprotect
#define dune_vm_map_phys	vmpl_vm_map_phys
#define dune_vm_map_pages	vmpl_vm_map_pages
#define dune_vm_unmap 		vmpl_vm_munmap
#define dune_vm_lookup		vmpl_vm_lookup

#define dune_vm_insert_page	vmpl_vm_insert_page
#define dune_vm_lookup_page	vmpl_vm_lookup_page

#define dune_vm_clone		vmpl_vm_clone
#define dune_vm_free		vmpl_vm_free
#define dune_vm_default_pgflt_handler	vmpl_mm_default_pgflt_handler

#define dune_vm_page_walk	vmpl_vm_page_walk

#endif