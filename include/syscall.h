#ifndef __VMPL_SYSCALL_
#define __VMPL_SYSCALL_

#define MSR_PROTOCOL 1
#ifdef MSR_PROTOCOL
#define GHCB_MSR 0xc0010130

/// 0xfff
#define GHCB_MSR_INFO_MASK 0xfff

#define GHCB_MSR_INFO(x) ((x) & GHCB_MSR_INFO_MASK)

#define GHCB_MSR_DATA(x) ((x) & ~GHCB_MSR_INFO_MASK)

/* GHCB Run at VMPL Request/Response */
/// 0x16
#define GHCB_MSR_VMPL_REQ 0x016
#define GHCB_MSR_VMPL_REQ_LEVEL(x) ((x) | GHCB_MSR_VMPL_REQ)
/// 0x17
#define GHCB_MSR_VMPL_RES 0x017
#define GHCB_MSR_VMPL_RESP_VAL(v) (v >> 32)

// Read MSR
static inline unsigned long __rdmsr(unsigned int msr) {
    unsigned int lo;
    unsigned int hi;

    __asm__ __volatile__("rdmsr"
                         : "=a"(lo), "=d"(hi)
                         : "c"(msr)
                         : "memory");

    return ((unsigned long)hi << 32) | lo;
}

// Write to MSR a given value
static inline void __wrmsr(unsigned int msr, unsigned long value) {
    unsigned int lo = value;
    unsigned int hi = value >> 32;

    __asm__ __volatile__("wrmsr"
                         :
                         : "c"(msr), "a"(lo), "d"(hi)
                         : "memory");
}

#define __syscall_prolog(__vmgexit)                        \
	do                                                     \
	{                                                      \
		unsigned short cs;                                 \
		__asm__ __volatile__("movw %%cs, %0" : "=r"(cs));  \
		if ((cs & 0x3) == 0)                               \
		{                                                  \
			unsigned long val, resp;                       \
			val = __rdmsr(GHCB_MSR);                       \
			__wrmsr(GHCB_MSR, GHCB_MSR_VMPL_REQ_LEVEL(0)); \
			__asm__ __vmgexit;                             \
			resp = __rdmsr(GHCB_MSR);                      \
			__wrmsr(GHCB_MSR, val);                        \
			if (GHCB_MSR_INFO(resp) != GHCB_MSR_VMPL_RES)  \
				ret = -1;                                  \
			if (GHCB_MSR_VMPL_RESP_VAL(resp) != 0)         \
				ret = -1;                                  \
			return ret;                                    \
		}                                                  \
	} while (0)
#endif

static __inline long __syscall0(long n)
{
	unsigned long ret;
	__syscall_prolog(__volatile__("vmgexit" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory"));
	__asm__ __volatile__("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
	return ret;
}

static __inline long __syscall1(long n, long a1)
{
    unsigned long ret;
    __syscall_prolog(__volatile__("vmgexit" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory"));
    __asm__ __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static __inline long __syscall2(long n, long a1, long a2)
{
    unsigned long ret;
    __syscall_prolog(__volatile__("vmgexit" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory"));
    __asm__ __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return ret;
}

static __inline long __syscall3(long n, long a1, long a2, long a3)
{
    unsigned long ret;
    __syscall_prolog(__volatile__("vmgexit" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory"));
    __asm__ __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

static __inline long __syscall4(long n, long a1, long a2, long a3, long a4)
{
    unsigned long ret;
    register long r10 __asm__("r10") = a4;
    __syscall_prolog(__volatile__("vmgexit" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory"));
    __asm__ __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

static __inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
    unsigned long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    __syscall_prolog(__volatile__("vmgexit" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory"));
    __asm__ __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
    return ret;
}

static __inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    unsigned long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __syscall_prolog(__volatile__("vmgexit" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory"));
    __asm__ __volatile__("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

#endif