#ifndef __VMPL_IOCTL_H
#define __VMPL_IOCTL_H

#include <stdint.h>

#include "vmpl-dev.h"

int vmpl_ioctl_set_pgtable_vmpl(int vmpl_fd, uint64_t gva, uint64_t page_size,
                                uint32_t attrs);
int vmpl_ioctl_set_user_vmpl(int vmpl_fd, uint64_t gva, uint64_t page_size,
							 uint32_t attrs);
int vmpl_ioctl_get_ghcb(int vmpl_fd, uint64_t *ghcb);
int vmpl_ioctl_get_cr3(int vmpl_fd, uint64_t *cr3);
int vmpl_ioctl_get_pages(int vmpl_fd, struct get_pages_t *param);
int vmpl_ioctl_get_layout(int vmpl_fd, struct vmpl_layout *layout);
int vmpl_ioctl_set_seimi(int vmpl_fd);
int vmpl_ioctl_trap_enable(int vmpl_fd, struct vmpl_trap_config *trap_config);
int vmpl_ioctl_trap_disable(int vmpl_fd);
int vmpl_ioctl_vmpl_run(int vmpl_fd, struct vmsa_config *vmsa_config);
#ifdef CONFIG_DUNE_BOOT
int dune_ioctl_trap_enable(int dune_fd, struct dune_trap_config *trap_config);
int dune_ioctl_trap_disable(int dune_fd);
int dune_ioctl_get_syscall(int dune_fd, uint64_t *syscall);
int dune_ioctl_get_layout(int dune_fd, struct dune_layout *layout);
#endif
#endif