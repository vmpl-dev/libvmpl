#ifndef _LIBVMPL_MM_H
#define _LIBVMPL_MM_H

#include <stdint.h>

#define pgtable_pa_to_va(pa) ((char *)(pa + 0xffff800000000000))
#define pgtable_va_to_pa(va) ((char *)(va - 0xffff800000000000))

#endif