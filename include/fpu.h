/*
 * fpu.h - x86 floating point, MMX, SSE, and AVX support for Dune
 */

#include <string.h>
#include <stdint.h>

struct fxsave_area {
	uint16_t cwd;
	uint16_t swd;
	uint16_t twd;
	uint16_t fop;
	uint64_t rip;
	uint64_t rdp;
	uint32_t mxcsr;
	uint32_t mxcsr_mask;
	uint32_t st_regs[32];   // 8 128-bit FP registers
	uint32_t xmm_regs[64];  // 16 128-bit XMM registers
	uint32_t padding[24];
} __attribute__((packed));

struct xsave_header {
	uint64_t xstate_bv;
	uint64_t reserved_zero[2];
	uint64_t reserved[5];
} __attribute__((packed));

struct xsave_area {
	struct fxsave_area	fxsave;
	struct xsave_header	header;
	uint32_t		ymm_regs[64]; // extends XMM registers to 256-bit
	/* FIXME: check CPUID, could be other extensions in the future */
} __attribute__((packed, aligned (64)));

struct fpu_area {
	/* we only support xsave, since it's available in nehalem and later */
	struct xsave_area	xsave;
};

static inline void fpu_xsave(struct fpu_area *fp, uint64_t mask)
{
	uint32_t lmask = mask;
	uint32_t umask = mask >> 32;

	asm volatile("xsaveq %0\n\t" : "=m"(fp->xsave) :
		     "a"(lmask), "d"(umask) :
		     "memory");
}

static inline void fpu_xsaveopt(struct fpu_area *fp, uint64_t mask)
{
	uint32_t lmask = mask;
	uint32_t umask = mask >> 32;

	asm volatile("xsaveoptq %0\n\t" : "=m"(fp->xsave) :
		     "a"(lmask), "d"(umask) :
		     "memory");
}

static inline void fpu_xrstor(struct fpu_area *fp, uint64_t mask)
{
	uint32_t lmask = mask;
	uint32_t umask = mask >> 32;

	asm volatile("xrstorq %0\n\t" : : "m"(fp->xsave),
		     "a"(lmask), "d"(umask) :
		     "memory");
}

/*
 * dune_fpu_init - initializes an fpu area
 * @fp: the fpu area
 */
static inline void dune_fpu_init(struct fpu_area *fp)
{
	memset(fp, 0, sizeof(struct fpu_area));
	fp->xsave.fxsave.cwd = 0x37f;
	fp->xsave.fxsave.twd = 0xffff;
	fp->xsave.fxsave.mxcsr = 0x1f80;
}

static inline void dune_fpu_dump(struct fpu_area *fpu)
{
    printf("fpu: cwd: %x swd: %x, twd: %x\n", fpu->xsave.fxsave.cwd, fpu->xsave.fxsave.swd, fpu->xsave.fxsave.twd);
    printf("fpu: fop: %x rip: %lx rdp: %x\n", fpu->xsave.fxsave.fop, fpu->xsave.fxsave.rip, fpu->xsave.fxsave.rdp);
    printf("fpu: mxcsr: %x mxcsr_mask: %x\n", fpu->xsave.fxsave.mxcsr, fpu->xsave.fxsave.mxcsr_mask);
    printf("fpu: st0: %f st1: %f st2: %f st3: %f st4: %f st5: %f st6: %f st7: %f\n",
           fpu->xsave.fxsave.st_regs[0], fpu->xsave.fxsave.st_regs[1], fpu->xsave.fxsave.st_regs[2],
           fpu->xsave.fxsave.st_regs[3], fpu->xsave.fxsave.st_regs[4], fpu->xsave.fxsave.st_regs[5],
           fpu->xsave.fxsave.st_regs[6], fpu->xsave.fxsave.st_regs[7]);
    printf("fpu: xmm0: %f xmm1: %f xmm2: %f xmm3: %f xmm4: %f xmm5: %f xmm6: %f xmm7: %f\n",
            fpu->xsave.fxsave.xmm_regs[0], fpu->xsave.fxsave.xmm_regs[1], fpu->xsave.fxsave.xmm_regs[2],
            fpu->xsave.fxsave.xmm_regs[3], fpu->xsave.fxsave.xmm_regs[4], fpu->xsave.fxsave.xmm_regs[5],
            fpu->xsave.fxsave.xmm_regs[6], fpu->xsave.fxsave.xmm_regs[7]);
}

/*
 * dune_fpu_load - loads an fpu area into fpu registers
 * @fp: the fpu area
 */
static inline void dune_fpu_load(struct fpu_area *fp)
{
	fpu_xrstor(fp, -1);
}

/*
 * dune_fpu_save - saves fpu registers to an fpu area
 * @fp: the fpu area
 * 
 * WARNING: Do not call this function on a memory region
 * that was not previously loaded with dune_fpu_load().
 * 
 * If you do, register state corruption might be possible. See
 * "XSAVEOPT Usage Guidlines" under the XSAVEOPT instruction
 * description in the Intel Manual Instruction Set Reference
 * for more details.
 */
static inline void dune_fpu_save(struct fpu_area *fp)
{
	// FIXME: need to check CPUID because only
	// sandybridge and later support XSAVEOPT
	fpu_xsaveopt(fp, -1);
}

/*
 * dune_fpu_save_safe - saves an fpu area from CPU registers
 * @fp: the fpu area
 * 
 * Works under all conditions, but may be slower.
 */
static inline void dune_fpu_save_safe(struct fpu_area *fp)
{
	fpu_xsave(fp, -1);
}
