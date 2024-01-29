#include <sys/mman.h>
#include <errno.h>

#include "vmpl-ioctl.h"
#include "seimi.h"
#include "log.h"

#ifdef CONFIG_VMPL_SEIMI
int setup_seimi(int dune_fd)
{
    int rc;

    log_info("Setting up SEIMI");
    rc = vmpl_ioctl_set_seimi(dune_fd);
    if (rc < 0) {
        log_err("Failed to setup SEIMI: %s", strerror(errno));
    }

    return rc;
}
#endif

void *sa_alloc(size_t length, bool need_ro, long *offset)
{
	char *seimi_user, *seimi_super;
    seimi_user = mmap((void *)SEIMI_MMAP_BASE_USER, length, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (seimi_user == MAP_FAILED)
		return NULL;

    // If the caller does not need a read-only region, return the user region directly.
    if (!need_ro) {
        return seimi_user;
    }

    seimi_super = mmap((void *)SEIMI_MMAP_BASE_SUPER, length, PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (seimi_super == MAP_FAILED)
        return NULL;

    *offset = (long)(seimi_super - seimi_user);

    return seimi_user;
}

bool sa_free(void *addr, size_t length)
{
    munmap(addr, length);
    return true;
}