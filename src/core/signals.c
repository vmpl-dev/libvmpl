#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <stddef.h>
#include "log.h"
#include "signals.h"

#ifdef CONFIG_VMPL_SIGNAL
void setup_signal(void)
{
    size_t i;
    log_info("setup signal");

    // disable signals for now until we have better support
    log_trace("disable signals for now until we have better support");
    for (i = 1; i < 32; i++) {
        struct sigaction sa;

        switch (i) {
        case SIGTSTP:
        case SIGSTOP:
        case SIGKILL:
        case SIGCHLD:
        case SIGINT:
        case SIGTERM:
            continue;
        }

        memset(&sa, 0, sizeof(sa));

        sa.sa_handler = SIG_IGN;

        if (sigaction(i, &sa, NULL) == -1)
            err(1, "sigaction() %d", i);
    }
}
#endif