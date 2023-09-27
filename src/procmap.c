#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "procmap.h"

const char* mapping_type_strings[PROCMAP_TYPE_COUNT] = {
    [PROCMAP_TYPE_UNKNOWN] = "Unknown",
    [PROCMAP_TYPE_FILE] = "File",
    [PROCMAP_TYPE_ANONYMOUS] = "Anonymous",
    [PROCMAP_TYPE_HEAP] = "Heap",
    [PROCMAP_TYPE_STACK] = "Stack",
    [PROCMAP_TYPE_VSYSCALL] = "Vsyscall",
    [PROCMAP_TYPE_VDSO] = "Vdso",
    [PROCMAP_TYPE_VVAR] = "Vvar"
};

MappingType get_mapping_type(const char *pathname)
{
  if (pathname[0] != '[' && pathname[0] != '\0')
          return PROCMAP_TYPE_FILE;
  if (pathname[0] == '\0')
          return PROCMAP_TYPE_ANONYMOUS;
  if (strcmp(pathname, "[heap]") == 0)
          return PROCMAP_TYPE_HEAP;
  if (strncmp(pathname, "[stack]", 7) == 0)
          return PROCMAP_TYPE_STACK;
  if (strcmp(pathname, "[vsyscall]") == 0)
          return PROCMAP_TYPE_VSYSCALL;
  if (strcmp(pathname, "[vdso]") == 0)
          return PROCMAP_TYPE_VDSO;
  if (strcmp(pathname, "[vvar]") == 0)
          return PROCMAP_TYPE_VVAR;
  return PROCMAP_TYPE_UNKNOWN;
}

const char* get_mapping_type_string(MappingType type) {
  return mapping_type_strings[type];
}

void parse_proc_maps(void (*callback)(MemoryMapping*)) {
  FILE* file = fopen("/proc/self/maps", "r");
  if (file == NULL) {
    printf("Error opening file: /proc/self/maps\n");
    return;
  }

  char line[4096];
  while (fgets(line, sizeof(line), file)) {
    MemoryMapping mapping;
    sscanf(line, "%lx-%lx %4s %lx %x:%x %d %s",
           &mapping.start, &mapping.end, mapping.perms,
           &mapping.offset, &mapping.dev_major, &mapping.dev_minor,
           &mapping.inode, mapping.pathname);
    callback(&mapping);
  }

  fclose(file);
}

void print_virtual_address(MemoryMapping* mapping) {
    printf("Virtual Address Range: 0x%lx-0x%lx, Permissions: %s\n", mapping->start, mapping->end, mapping->perms);
}

void print_mapping(MemoryMapping* mapping) {
  printf("Start: %lx\n", mapping->start);
  printf("End: %lx\n", mapping->end);
  printf("Perms: %s\n", mapping->perms);
  printf("Offset: %lx\n", mapping->offset);
  printf("Dev: %x:%x\n", mapping->dev_major, mapping->dev_minor);
  printf("Inode: %d\n", mapping->inode);
  printf("pathname: %s\n", mapping->pathname);
  printf("Type: %s\n\n", get_mapping_type_string(get_mapping_type(mapping->pathname)));
}

void print_mapping_oneline(MemoryMapping* mapping) {
  printf("0x%016lx-0x%016lx %c%c%c%c %08lx %s\n",
         mapping->start, mapping->end, mapping->perms[0], mapping->perms[1],
         mapping->perms[2], mapping->perms[3], mapping->offset, mapping->pathname);
}

void example_callback(MemoryMapping* mapping) {
  printf("Virtual Address Range: 0x%lx-0x%lx\n", mapping->start, mapping->end);
}