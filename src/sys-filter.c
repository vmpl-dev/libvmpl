
#include <stdbool.h>
#include <stdlib.h>

#include "vmpl.h"
#include "sys-filter.h"

static struct syscall_filter *syscall_filters = NULL;

void init_syscall_filter(struct syscall_filter* filter)
{
	filter->next = NULL;
}

bool register_syscall_filter_single(struct syscall_filter *new_filter)
{
	if (!syscall_filters) {
		syscall_filters = new_filter;
	} else {
		struct syscall_filter *current = syscall_filters;
		struct syscall_filter *prev = NULL;
		while (current && current->priority <= new_filter->priority) {
			prev = current;
			current = current->next;
		}
		if (prev) {
			prev->next = new_filter;
			new_filter->next = current;
		} else {
			new_filter->next = syscall_filters;
			syscall_filters = new_filter;
		}
	}

	return true;
}

static default_error_handler(struct dune_tf *tf)
{
	printf("Error: syscall filter failed\n");
	dune_die();
}

bool register_syscall_filter(bool (*filter)(struct dune_tf *tf))
{
	struct syscall_filter *new_filter = (struct syscall_filter *)malloc(sizeof(struct syscall_filter));
	if (!new_filter) {
		return false;
	}

	init_syscall_filter(new_filter);
	new_filter->syscall_number = -1;
	new_filter->error_handler = &default_error_handler;
	new_filter->filter = filter;
	new_filter->priority = NORMAL;

	return register_syscall_filter_single(new_filter);
}

bool apply_syscall_filters(struct dune_tf *tf)
{
	struct syscall_filter *current = syscall_filters;
	while (current) {
		// If the syscall number is set, only apply the filter if the syscall
		// number matches the filter's syscall number, otherwise skip the filter.
		if ((current->syscall_number != -1)
			&& (current->syscall_number != tf->rax)) {
			current = current->next;
			continue;
		}

		// If the filter returns false, the syscall should be blocked. If the
		// filter returns true, the syscall should be allowed.
		if (current->filter && !current->filter(tf)) {
			// If the filter returns false, call the error handler if it is set.
			// If the error handler is not set, return false to indicate that the
			// syscall should be blocked.
			if (current->error_handler) {
				current->error_handler(tf);
			} else {
				return false;
			}
		}
		current = current->next;
	}
	return true;
}

bool remove_syscall_filter(bool (*filter)(struct dune_tf *tf))
{
	struct syscall_filter *current = syscall_filters;
	struct syscall_filter *prev = NULL;

	while (current) {
		if (current->filter == filter) {
			if (prev) {
				prev->next = current->next;
			} else {
				syscall_filters = current->next;
			}
			free(current);
			return true;
		}
		prev = current;
		current = current->next;
	}

	return false;
}

void clear_syscall_filters()
{
	struct syscall_filter *current = syscall_filters;
	while (current) {
		struct syscall_filter *next = current->next;
		free(current);
		current = next;
	}
	syscall_filters = NULL;
}

