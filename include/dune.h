#ifndef __DUNE_H_
#define __DUNE_H_

#include "vmpl.h"
#include "mm.h"

#define dune_flush_tlb() flush_tlb()

#define dune_fd vmpl_fd
#define pgroot  this_pgd

#define dune_enter()          vmpl_enter(1, NULL)
#define dune_init_and_enter() vmpl_enter(1, NULL)

#define dune_va_to_pa       pgtable_va_to_pa
#define dune_vm_mprotect	vmpl_vm_mprotect
#define dune_vm_map_phys	vmpl_vm_map_phys
#define dune_vm_map_pages	vmpl_vm_map_pages
#define dune_vm_unmap 		vmpl_vm_unmap
#define dune_vm_lookup		vmpl_vm_lookup

#define dune_vm_insert_page	vmpl_vm_insert_page
#define dune_vm_lookup_page	vmpl_vm_lookup_page

#define dune_vm_clone		vmpl_vm_clone
#define dune_vm_free		vmpl_vm_free
#define dune_vm_default_pgflt_handler	vmpl_vm_default_pgflt_handler

#define dune_vm_page_walk	vmpl_vm_page_walk

#endif