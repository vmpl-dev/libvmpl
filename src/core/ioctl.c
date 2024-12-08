#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "ioctl.h"
#include "log.h"

int vmpl_ioctl_create_vm(int vmpl_fd) {
    int rc;
    rc = ioctl(vmpl_fd, VMPL_IOCTL_CREATE_VM);
    if (rc < 0) {
        log_err("Failed to create VMPL: %s", strerror(errno));
        return -errno;
    }

    return rc;
}

int vmpl_ioctl_set_pgtable_vmpl(int vmpl_fd, uint64_t gva, uint64_t page_size, uint32_t attrs) {
    int rc;
    struct vmpl_args_t args = {
        .gva = gva,
        .page_size = page_size,
        .attrs = attrs,
    };

    rc = ioctl(vmpl_fd, VMPL_IOCTL_SET_PGTABLE_VMPL, &args);
    if (rc < 0) {
        log_err("Failed to setup PGTABLE VMPL: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

int vmpl_ioctl_set_user_vmpl(int vmpl_fd, uint64_t gva, uint64_t page_size, uint32_t attrs) {
    int rc;
    struct vmpl_args_t args = {
        .gva = gva,
        .page_size = page_size,
        .attrs = attrs,
    };

    rc = ioctl(vmpl_fd, VMPL_IOCTL_SET_PAGE_VMPL, &args);
    if (rc < 0) {
        log_err("Failed to setup user VMPL: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

int vmpl_ioctl_create_vcpu(int vmpl_fd, struct vcpu_config *config) {
    int rc;
    rc = ioctl(vmpl_fd, VMPL_IOCTL_CREATE_VCPU, config);
    if (rc < 0) {
        log_err("Failed to create VCPU: %s", strerror(errno));
        return -errno;
    }

    return rc;
}

int vmpl_ioctl_get_layout(int vmpl_fd, struct vmpl_layout *layout) {
    int rc;
    rc = ioctl(vmpl_fd, VMPL_IOCTL_GET_LAYOUT, layout);
    if (rc < 0) {
        log_err("Failed to get layout: %s", strerror(errno));
        return -errno;
    }
}

int vmpl_ioctl_get_ghcb(int vmpl_fd, uint64_t *ghcb) {
    int rc;
    rc = ioctl(vmpl_fd, VMPL_IOCTL_GET_GHCB, ghcb);
    if (rc != 0) {
        perror("dune: failed to get GHCB");
        return rc;
    }

    log_debug("dune: GHCB at 0x%lx", ghcb);
    return 0;
}

int vmpl_ioctl_get_cr3(int vmpl_fd, uint64_t *cr3) {
    int rc;
    rc = ioctl(vmpl_fd, VMPL_IOCTL_GET_CR3, cr3);
    if (rc != 0) {
        perror("dune: failed to get CR3");
        return rc;
    }

    log_debug("dune: CR3 at 0x%lx", cr3);
    return 0;
}

int vmpl_ioctl_get_pages(int vmpl_fd, struct get_pages_t *param) {
    int rc;
	rc = ioctl(vmpl_fd, VMPL_IOCTL_GET_PAGES, param);
    if (rc != 0) {
        perror("dune: failed to get pages");
        return -errno;
    }

    return 0;
}

int vmpl_ioctl_set_seimi(int vmpl_fd, struct vmpl_seimi_t *seimi) {
	int rc;
	rc = ioctl(vmpl_fd, VMPL_IOCTL_SET_SEIMI, seimi);
	if (rc < 0) {
        log_err("Failed to setup SEIMI: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

int vmpl_ioctl_set_config(int vmpl_fd, struct vcpu_config *config) {
    int rc;
    rc = ioctl(vmpl_fd, VMPL_IOCTL_SET_CONFIG, config);
    if (rc < 0) {
        log_err("Failed to setup config: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

int vmpl_ioctl_get_config(int vmpl_fd, struct vcpu_config *config) {
    int rc;
    rc = ioctl(vmpl_fd, VMPL_IOCTL_GET_CONFIG, config);
    if (rc < 0) {
        log_err("Failed to get config: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

int vmpl_ioctl_vmpl_run(int vmpl_fd, struct dune_config *dune_config) {
    int rc;
    rc = ioctl(vmpl_fd, VMPL_IOCTL_VMPL_RUN, dune_config);
    if (rc < 0) {
        log_err("Failed to run VMPL: %s", strerror(errno));
        return -errno;
    }

    return rc;
}

int dune_ioctl_trap_enable(int dune_fd, struct dune_trap_config *trap_config) {
    int rc;
    rc = ioctl(dune_fd, DUNE_TRAP_ENABLE, trap_config);
    if (rc < 0) {
        log_err("Failed to enable trap: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

int dune_ioctl_trap_disable(int dune_fd) {
    int rc;
    rc = ioctl(dune_fd, DUNE_TRAP_DISABLE);
    if (rc < 0) {
        log_err("Failed to disable trap: %s", strerror(errno));
        return -errno;
    }

    return 0;
}

int dune_ioctl_get_syscall(int dune_fd, uint64_t *syscall) {
    int rc;
    rc = ioctl(dune_fd, DUNE_GET_SYSCALL, syscall);
    if (rc != 0) {
        perror("dune: failed to get syscall");
        return rc;
    }

    log_debug("dune: syscall at 0x%lx", syscall);
    return 0;
}

int dune_ioctl_get_layout(int dune_fd, struct dune_layout *layout) {
    int rc;
    rc = ioctl(dune_fd, DUNE_GET_LAYOUT, layout);
    if (rc != 0) {
        perror("dune: failed to get layout");
        return rc;
    }

    // log phys_limit, base_map and base_stack of the layout
    log_debug("dune: phys_limit at 0x%lx", layout->phys_limit);
    log_debug("dune: base_map at 0x%lx", layout->base_map);
    log_debug("dune: base_stack at 0x%lx", layout->base_stack);

    return 0;
}