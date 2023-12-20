#ifndef __SEV_H_
#define __SEV_H_

#include <stdint.h>

struct deposit_mem_entry_t {
    uint64_t page_size : 2;
    uint64_t reserved : 10;
    uint64_t gfn : 52;
};

typedef struct deposit_mem_request_t {
    uint16_t num_entries;
    uint16_t next;
    uint32_t reserved;
    struct deposit_mem_entry_t entries[0];
} deposit_mem_request;

typedef struct withdraw_mem_entry_t {
    uint64_t reserved : 12;
    uint64_t gfn : 52;
} withdraw_mem_entry;

typedef struct withdraw_mem_request_t {
    uint16_t num_entries;
    uint8_t unused[6];
    uint32_t reserved;
    struct withdraw_mem_entry_t entries[0];
} withdraw_mem_request;

#endif /* __SEV_H_ */