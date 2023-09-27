// procmap.h

#ifndef PROCMAP_H
#define PROCMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  unsigned long start;
  unsigned long end;
  char perms[5];
  unsigned long offset;
  int dev_major;
  int dev_minor;
  int inode;
  char pathname[4096];
} MemoryMapping;

typedef enum {
    PROCMAP_TYPE_UNKNOWN = 0x00,
    PROCMAP_TYPE_FILE = 0x01,
    PROCMAP_TYPE_ANONYMOUS = 0x02,
    PROCMAP_TYPE_HEAP = 0x03,
    PROCMAP_TYPE_STACK = 0x04,
    PROCMAP_TYPE_VSYSCALL = 0x05,
    PROCMAP_TYPE_VDSO = 0x06,
    PROCMAP_TYPE_VVAR = 0x07,
    PROCMAP_TYPE_COUNT  // 增加一个枚举以表示枚举数量
} MappingType;

extern const char *mapping_type_strings[];

MappingType get_mapping_type(const char* pathname);
const char* get_mapping_type_string(MappingType type);
void parse_proc_maps(void (*callback)(MemoryMapping*));
void print_virtual_address(MemoryMapping *mapping);
void print_mapping(MemoryMapping *mapping);
void print_mapping_oneline(MemoryMapping* mapping);
void example_callback(MemoryMapping* mapping);

#endif /* PROCMAP_H */