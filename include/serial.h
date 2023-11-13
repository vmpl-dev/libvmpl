#ifndef __SERIAL_H_
#define __SERIAL_H_

void serial_out(const char *string);
void serial_in(char *string);
#ifdef CONFIG_SERIAL_PORT
void serial_init();
#else
static inline void serial_init(void) {}
#endif

#endif