#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <asm-generic/unistd.h>
#include <hotcalls/hotcalls.h>

#include "log.h"
#include "percpu.h"

// Define the maximum number of system calls
#define MAX_SYSCALLS __NR_syscalls

// Define the hotcalls bitmap
static uint64_t hotcalls_bitmap[MAX_SYSCALLS / 64 + 1] = { 0 };

// Register a system call as a hotcall
void register_hotcall(long syscall) {
	if (syscall >= 0 && syscall < MAX_SYSCALLS) {
		uint64_t mask = 1ULL << (syscall % 64);
		hotcalls_bitmap[syscall / 64] |= mask;
	}
}

// Unregister a system call as a hotcall
void unregister_hotcall(long syscall) {
	if (syscall >= 0 && syscall < MAX_SYSCALLS) {
		uint64_t mask = ~(1ULL << (syscall % 64));
		hotcalls_bitmap[syscall / 64] &= mask;
	}
}

// Check if a system call is a hotcall
bool is_hotcall(long syscall) {
	if (syscall >= 0 && syscall < MAX_SYSCALLS) {
		uint64_t mask = 1ULL << (syscall % 64);
		return (hotcalls_bitmap[syscall / 64] & mask) != 0;
	}
	return false;
}

long vmpl_hotcalls_call(struct dune_tf *tf)
{
    hotcall_args_t args = {
        .sysnr = tf->rax,
        .rdi = tf->rdi,
        .rsi = tf->rsi,
        .rdx = tf->rdx,
        .r10 = tf->rcx,
        .r8 = tf->r8,
        .r9 = tf->r9,
    };

	if (!is_hotcall(tf->rax)) {
		return -ENOSYS;
	}

	return hotcalls_call(&args);
}

long exec_hotcall(long nr, ...)
{
	va_list args;
	hotcall_args_t hotcall_args = {
		.sysnr = nr,
	};

	va_start(args, nr);
	hotcall_args.rdi = va_arg(args, long);
	hotcall_args.rsi = va_arg(args, long);
	hotcall_args.rdx = va_arg(args, long);
	hotcall_args.r10 = va_arg(args, long);
	hotcall_args.r8 = va_arg(args, long);
	hotcall_args.r9 = va_arg(args, long);
	va_end(args);

	if (!is_hotcall(nr)) {
		return -ENOSYS;
	}

	if (!hotcalls_initialized()) {
		return -ENOSYS;
	}

	return hotcalls_call(&hotcall_args);
}

static size_t load_hotcalls(char *hotcalls_conf)
{
	// Load hotcalls configuration from file.
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char syscall_name[64];
	int syscall;
	size_t nr_hotcalls = 0;

	if (hotcalls_conf == NULL) {
		log_warn("HOTCALLS_CONFIG_FILE not set");
		return 0;
	}

	fp = fopen(hotcalls_conf, "r");
	if (fp == NULL) {
		log_err("failed to open %s", hotcalls_conf);
		return 0;
	}

	while ((read = getline(&line, &len, fp)) != -1) {
		if (line[0] == '#' || line[0] == '\n') {
			continue;
		}
		sscanf(line, "define %s %d", syscall_name, &syscall);
		log_debug("registering hotcall %s %d", syscall_name, syscall);
		register_hotcall(syscall);
		nr_hotcalls++;
	}

	if (nr_hotcalls == 0) {
		log_warn("no hotcalls registered");
	} else {
		log_info("registered %lu hotcalls", nr_hotcalls);
	}

	if (line) {
		free(line);
	}

	fclose(fp);

	return nr_hotcalls;
}

static void hotcalls_cleanup()
{
	hotcalls_teardown();
}


void setup_hotcalls()
{
	char *hotcalls_conf;

	log_info("setup hotcalls");

	hotcalls_conf = getenv("HOTCALLS_CONFIG_FILE");
	if (load_hotcalls(hotcalls_conf) > 0) {
		// Register cleanup function
		atexit(hotcalls_cleanup);

		// Initialize hotcalls
		hotcalls_setup(1);

		log_success("hotcalls enabled");
	} else {
		log_warn("hotcalls not enabled");
	}
}

#ifdef CONFIG_VMPL_HOTCALLS
void hotcalls_enable(struct dune_percpu *percpu)
{
	percpu->hotcall = exec_hotcall;
}
#endif