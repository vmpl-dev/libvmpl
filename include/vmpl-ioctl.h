#ifndef __VMPL_IOCTL_H
#define __VMPL_IOCTL_H

#include <stdint.h>

#include "vmpl-dev.h"

#ifdef CONFIG_VMPL_PGTABLE_PROTECTION
int vmpl_ioctl_set_pgtable_vmpl(int vmpl_fd, uint64_t gva, uint64_t page_size,
                                uint32_t attrs);
#else
static inline int vmpl_ioctl_set_pgtable_vmpl(vmpl_fd, gva, page_size, attrs) {
	return 0;
}
#endif
int vmpl_ioctl_set_user_vmpl(int vmpl_fd, uint64_t gva, uint64_t page_size,
							 uint32_t attrs);
int vmpl_ioctl_get_ghcb(int vmpl_fd, uint64_t *ghcb);
int vmpl_ioctl_get_cr3(int vmpl_fd, uint64_t *cr3);
int vmpl_ioctl_get_pages(int vmpl_fd, uint64_t *phys);
int vmpl_ioctl_set_seimi(int vmpl_fd);
int vmpl_ioctl_vmpl_run(int vmpl_fd, struct vmsa_config *vmsa_config);
int dune_ioctl_get_syscall(int dune_fd, uint64_t *syscall);
int dune_ioctl_get_layout(int dune_fd, struct dune_layout *layout);
#endif