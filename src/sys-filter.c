
#include <stdbool.h>
#include <stdlib.h>

#include "vmpl.h"
#include "sys-filter.h"

static struct syscall_filter *syscall_filters = NULL;

bool register_syscall_filter_priority(bool (*filter)(struct dune_tf *tf), filter_priority priority)
{
	struct syscall_filter *new_filter = malloc(sizeof(struct syscall_filter));
	if (!new_filter)
		return false;

	new_filter->filter = filter;
	new_filter->priority = priority;
	new_filter->next = NULL;

	if (!syscall_filters) {
		syscall_filters = new_filter;
	} else {
		struct syscall_filter *current = syscall_filters;
		struct syscall_filter *prev = NULL;
		while (current && current->priority <= priority) {
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

bool register_syscall_filter(bool (*filter)(struct dune_tf *tf))
{
	return register_syscall_filter_priority(filter, NORMAL);
}

bool apply_syscall_filters(struct dune_tf *tf)
{
	struct syscall_filter *current = syscall_filters;
	while (current) {
		if (current->filter && !current->filter(tf))
			return false;
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

