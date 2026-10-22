/* Runtime support for C lifted from 32-bit x86 (Watcom/DOS4GW flat model).
 *
 * Guest memory is one flat byte array; guest address == offset into it,
 * matching DOS/4GW's zero-based flat selectors.  Out-of-range accesses and
 * runaway loops longjmp back to the caller of the lifted entry point.
 */
#ifndef RECOMP_X86_H
#define RECOMP_X86_H

#include <math.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

enum { EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI };   /* x86 register encoding order */

/* STOP_BADRET: a `ret` popped something other than its caller's return address.
 * STOP_TRAP: an instruction the lifter does not translate was reached.
 * STOP_EXIT: the program asked to terminate (runtime HLE). */
enum { STOP_OK = 0, STOP_FAULT = 1, STOP_BUDGET = 2, STOP_DIVIDE = 3, STOP_BADRET = 4,
       STOP_TRAP = 5, STOP_EXIT = 6 };

enum { SEG_ES, SEG_CS, SEG_SS, SEG_DS, SEG_FS, SEG_GS };  /* x86 encoding order */

typedef struct Flags {
    uint8_t cf, zf, sf, of, pf, df;
} Flags;

typedef struct Cpu Cpu;

/* Hooks the host runtime provides (NULL: the lifted code stops with STOP_TRAP). */
typedef struct Hooks {
    void (*interrupt)(Cpu *c, int vector, uint32_t at);        /* `int n` */
    uint32_t (*port_in)(Cpu *c, uint32_t port, int bytes);
    void (*port_out)(Cpu *c, uint32_t port, uint32_t value, int bytes);
    void (*call)(Cpu *c, uint32_t target, uint32_t at);        /* indirect / unlifted call */
    void (*trap)(Cpu *c, uint32_t at, const char *what);       /* untranslated instruction */
    uint32_t (*selector_base)(Cpu *c, uint16_t sel);            /* DPMI descriptor base */
    void (*hle)(Cpu *c, uint32_t func);                          /* function replaced by the runtime */
    int (*wrap)(Cpu *c, uint32_t func);       /* lift.py WRAP: nonzero = handled, original skipped */
    /* Memory-mapped device in [mmio_lo, mmio_hi) (e.g. planar VGA memory). */
    uint32_t (*mmio_read)(Cpu *c, uint32_t addr, int bytes);
    void (*mmio_write)(Cpu *c, uint32_t addr, uint32_t value, int bytes);
    /* Called when the branch budget runs out instead of stopping: the runtime
     * delivers timer interrupts here and sets a new budget. */
    void (*budget)(Cpu *c, uint32_t at);
} Hooks;

struct Cpu {
    uint32_t r[8];
    Flags f;               /* flags as of the last call/return boundary */
    uint16_t sreg[6];
    uint32_t sbase[6];     /* linear base per segment register (flat: 0) */
    uint8_t *mem;
    uint32_t mem_size;
    int64_t budget;        /* decremented at every backward branch */
    jmp_buf stop;
    uint32_t fault_addr;
    uint32_t ro_lo, ro_hi;  /* guest code: writes here fault (no self-modifying game code) */
    uint32_t ret_to;        /* return address popped by the last `ret` */
    const Hooks *hooks;
    void *host;             /* runtime state */
    uint32_t bad_call, bad_expect;   /* details of the last STOP_BADRET */
    uint32_t mmio_lo, mmio_hi;       /* accesses here go to hooks->mmio_* (empty: none) */
    double st[8];           /* x87 registers (double precision), ST(i) = st[(ftop + i) & 7] */
    uint32_t ftop;
    uint16_t fsw, fcw;      /* status word without TOP; control word */
#ifdef RECOMP_TRACE
    uint32_t trail[64];     /* most recently entered functions (ring) */
    uint32_t trail_pos;
    uint32_t stack[256];    /* shadow call stack of lifted functions */
    uint32_t depth;
    uint32_t dump_at;       /* function whose entry state is dumped (WAR_DUMP_AT) */
    uint32_t watch_lo, watch_hi;   /* writes here are reported (WAR_WATCH) */
#endif
};

#ifdef RECOMP_TRACE
void x86_on_enter(Cpu *c, uint32_t addr);          /* runtime: checkpoint dumps */
#define X86_ENTER(c, a) ((c)->trail[(c)->trail_pos++ & 63] = (a), \
                         (c)->stack[(c)->depth++ & 255] = (a), \
                         (a) == (c)->dump_at ? x86_on_enter((c), (a)) : (void)0)
#define X86_LEAVE(c) ((c)->depth--)
#else
#define X86_ENTER(c, a) ((void)0)
#define X86_LEAVE(c) ((void)0)
#endif

static inline void x86_stop(Cpu *c, int why, uint32_t addr) {
    c->fault_addr = addr;
    longjmp(c->stop, why);
}

/* A call returned to something other than the address it pushed. */
static inline void x86_badret(Cpu *c, uint32_t call_at, uint32_t expected) {
    c->bad_call = call_at;
    c->bad_expect = expected;
    x86_stop(c, STOP_BADRET, c->ret_to);
}

static inline uint8_t *x86_ptr(Cpu *c, uint32_t a, uint32_t n) {
    if (a > c->mem_size || c->mem_size - a < n) x86_stop(c, STOP_FAULT, a);
    return c->mem + a;
}

/* Games built with -DX86_HAVE_MMIO route [mmio_lo, mmio_hi) to the runtime;
 * others pay nothing for it. */
#ifdef X86_HAVE_MMIO
#define X86_MMIO(c, a) ((a) < (c)->mmio_hi && (a) >= (c)->mmio_lo)
#else
#define X86_MMIO(c, a) 0
#endif
static inline uint32_t rd8(Cpu *c, uint32_t a) {
    if (X86_MMIO(c, a)) return c->hooks->mmio_read(c, a, 1);
    return *x86_ptr(c, a, 1);
}
static inline uint32_t rd16(Cpu *c, uint32_t a) {
    if (X86_MMIO(c, a)) return c->hooks->mmio_read(c, a, 2);
    uint16_t v; memcpy(&v, x86_ptr(c, a, 2), 2); return v;
}
static inline uint32_t rd32(Cpu *c, uint32_t a) {
    if (X86_MMIO(c, a)) return c->hooks->mmio_read(c, a, 4);
    uint32_t v; memcpy(&v, x86_ptr(c, a, 4), 4); return v;
}
#ifdef RECOMP_TRACE
void x86_on_watch(Cpu *c, uint32_t addr, uint32_t n);   /* runtime: WAR_WATCH hit */
#endif
static inline uint8_t *x86_wptr(Cpu *c, uint32_t a, uint32_t n) {
    if (a < c->ro_hi && a + n > c->ro_lo) x86_stop(c, STOP_FAULT, a);
#ifdef RECOMP_TRACE
    if (a < c->watch_hi && a + n > c->watch_lo) x86_on_watch(c, a, n);
#endif
    return x86_ptr(c, a, n);
}
static inline void wr8(Cpu *c, uint32_t a, uint32_t v) {
    if (X86_MMIO(c, a)) { c->hooks->mmio_write(c, a, v, 1); return; }
    *x86_wptr(c, a, 1) = (uint8_t)v;
}
static inline void wr16(Cpu *c, uint32_t a, uint32_t v) {
    if (X86_MMIO(c, a)) { c->hooks->mmio_write(c, a, v, 2); return; }
    uint16_t x = (uint16_t)v; memcpy(x86_wptr(c, a, 2), &x, 2);
}
static inline void wr32(Cpu *c, uint32_t a, uint32_t v) {
    if (X86_MMIO(c, a)) { c->hooks->mmio_write(c, a, v, 4); return; }
    memcpy(x86_wptr(c, a, 4), &v, 4);
}

static inline void x86_tick(Cpu *c, uint32_t at) {
    if (--c->budget < 0) {
        if (c->hooks && c->hooks->budget) c->hooks->budget(c, at);
        else x86_stop(c, STOP_BUDGET, at);
    }
}

static inline uint8_t parity8(uint32_t v) { return !__builtin_parity(v & 0xFF); }

/* ---- runtime hooks ---------------------------------------------------------- */
static inline void x86_int(Cpu *c, int vector, uint32_t at) {
    if (!c->hooks || !c->hooks->interrupt) x86_stop(c, STOP_TRAP, at);
    c->hooks->interrupt(c, vector, at);
}
static inline uint32_t x86_in(Cpu *c, uint32_t port, int bytes, uint32_t at) {
    if (!c->hooks || !c->hooks->port_in) x86_stop(c, STOP_TRAP, at);
    return c->hooks->port_in(c, port & 0xFFFF, bytes);
}
static inline void x86_out(Cpu *c, uint32_t port, uint32_t v, int bytes, uint32_t at) {
    if (!c->hooks || !c->hooks->port_out) x86_stop(c, STOP_TRAP, at);
    c->hooks->port_out(c, port & 0xFFFF, v, bytes);
}
static inline void x86_call(Cpu *c, uint32_t target, uint32_t at) {
    if (!c->hooks || !c->hooks->call) x86_stop(c, STOP_TRAP, at);
    c->hooks->call(c, target, at);
}
static inline void x86_hle(Cpu *c, uint32_t func) {
    if (!c->hooks || !c->hooks->hle) x86_stop(c, STOP_TRAP, func);
    c->hooks->hle(c, func);
}
static inline int x86_wrap(Cpu *c, uint32_t func) {
    return c->hooks && c->hooks->wrap ? c->hooks->wrap(c, func) : 0;
}
static inline void x86_trap(Cpu *c, uint32_t at, const char *what) {
    if (c->hooks && c->hooks->trap) c->hooks->trap(c, at, what);
    x86_stop(c, STOP_TRAP, at);
}

/* Loading a segment register: flat (base 0) unless the runtime knows the selector. */
static inline void x86_load_seg(Cpu *c, int seg, uint32_t sel) {
    c->sreg[seg] = (uint16_t)sel;
    c->sbase[seg] = (c->hooks && c->hooks->selector_base) ? c->hooks->selector_base(c, (uint16_t)sel) : 0;
}

/* EFLAGS image for pushf/popf/iret (IF reported set, reserved bit 1 set). */
static inline uint32_t x86_pack_flags(const Flags *f) {
    return 0x202u | f->cf | (uint32_t)f->pf << 2 | (uint32_t)f->zf << 6 | (uint32_t)f->sf << 7 |
           (uint32_t)f->df << 10 | (uint32_t)f->of << 11;
}
static inline void x86_unpack_flags(Flags *f, uint32_t v) {
    f->cf = v & 1; f->pf = (v >> 2) & 1; f->zf = (v >> 6) & 1; f->sf = (v >> 7) & 1;
    f->df = (v >> 10) & 1; f->of = (v >> 11) & 1;
}

/* ---- ALU helpers, one set per operand width ---------------------------- */
#define X86_ALU(BITS, T, ST)                                                          \
static inline uint32_t sz_##BITS(Flags *f, uint32_t r) {                              \
    T v = (T)r; f->zf = v == 0; f->sf = (ST)v < 0; f->pf = parity8(v); return v;      \
}                                                                                     \
static inline uint32_t add##BITS(Flags *f, uint32_t a, uint32_t b, uint32_t cin) {    \
    T x = (T)a, y = (T)b; uint64_t w = (uint64_t)x + y + cin; T r = (T)w;             \
    f->cf = (w >> BITS) & 1; f->of = (ST)((x ^ r) & (y ^ r)) < 0; return sz_##BITS(f, r); \
}                                                                                     \
static inline uint32_t sub##BITS(Flags *f, uint32_t a, uint32_t b, uint32_t bin) {    \
    T x = (T)a, y = (T)b; T r = (T)(x - y - bin);                                     \
    f->cf = (uint64_t)x < (uint64_t)y + bin; f->of = (ST)((x ^ y) & (x ^ r)) < 0;     \
    return sz_##BITS(f, r);                                                           \
}                                                                                     \
static inline uint32_t logic##BITS(Flags *f, uint32_t r) {                            \
    f->cf = 0; f->of = 0; return sz_##BITS(f, r);                                     \
}                                                                                     \
static inline uint32_t inc##BITS(Flags *f, uint32_t a) {                              \
    T r = (T)(a + 1); f->of = r == (T)((T)1 << (BITS - 1)); return sz_##BITS(f, r);   \
}                                                                                     \
static inline uint32_t dec##BITS(Flags *f, uint32_t a) {                              \
    T r = (T)(a - 1); f->of = (T)a == (T)((T)1 << (BITS - 1)); return sz_##BITS(f, r); \
}                                                                                     \
static inline uint32_t neg##BITS(Flags *f, uint32_t a) {                              \
    uint32_t r = sub##BITS(f, 0, a, 0); f->cf = (T)a != 0; return r;                  \
}                                                                                     \
static inline uint32_t shl##BITS(Flags *f, uint32_t a, uint32_t n) {                  \
    n &= 31; if (!n) return (T)a;                                                     \
    T x = (T)a; T r = n >= BITS ? 0 : (T)(x << n);                                    \
    f->cf = n > BITS ? 0 : (x >> (BITS - n)) & 1;                                     \
    f->of = ((ST)r < 0) ^ f->cf; return sz_##BITS(f, r);                              \
}                                                                                     \
static inline uint32_t shr##BITS(Flags *f, uint32_t a, uint32_t n) {                  \
    n &= 31; if (!n) return (T)a;                                                     \
    T x = (T)a; T r = n >= BITS ? 0 : (T)(x >> n);                                    \
    f->cf = n > BITS ? 0 : (x >> (n - 1)) & 1;                                        \
    f->of = (ST)x < 0; return sz_##BITS(f, r);                                        \
}                                                                                     \
static inline uint32_t sar##BITS(Flags *f, uint32_t a, uint32_t n) {                  \
    n &= 31; if (!n) return (T)a;                                                     \
    ST x = (ST)a; uint32_t k = n >= BITS ? BITS - 1 : n;                              \
    T r = (T)(x >> k); f->cf = (x >> (k - (n >= BITS ? 0 : 1))) & 1;                  \
    f->of = 0; return sz_##BITS(f, r);                                                \
}                                                                                     \
static inline uint32_t rol##BITS(Flags *f, uint32_t a, uint32_t n) {                  \
    n &= 31; if (!n) return (T)a;                                                     \
    T x = (T)a; uint32_t k = n % BITS; T r = k ? (T)((x << k) | (x >> (BITS - k))) : x; \
    f->cf = r & 1; f->of = (((ST)r < 0) ^ f->cf); return r;                           \
}                                                                                     \
static inline uint32_t ror##BITS(Flags *f, uint32_t a, uint32_t n) {                  \
    n &= 31; if (!n) return (T)a;                                                     \
    T x = (T)a; uint32_t k = n % BITS; T r = k ? (T)((x >> k) | (x << (BITS - k))) : x; \
    f->cf = (ST)r < 0; f->of = ((r >> (BITS - 1)) ^ (r >> (BITS - 2))) & 1; return r; \
}

/* rotate through carry */
#define X86_RC(BITS, T)                                                               \
static inline uint32_t rcl##BITS(Flags *f, uint32_t a, uint32_t n) {                  \
    n = (n & 31) % (BITS + 1); T x = (T)a;                                            \
    for (uint32_t k = 0; k < n; k++) { uint8_t c = (x >> (BITS - 1)) & 1; x = (T)((x << 1) | f->cf); f->cf = c; } \
    if (n == 1) f->of = ((x >> (BITS - 1)) & 1) ^ f->cf;                              \
    return x;                                                                         \
}                                                                                     \
static inline uint32_t rcr##BITS(Flags *f, uint32_t a, uint32_t n) {                  \
    n = (n & 31) % (BITS + 1); T x = (T)a;                                            \
    if (n == 1) f->of = ((x >> (BITS - 1)) & 1) ^ f->cf;                              \
    for (uint32_t k = 0; k < n; k++) { uint8_t c = x & 1; x = (T)((x >> 1) | ((T)f->cf << (BITS - 1))); f->cf = c; } \
    return x;                                                                         \
}

X86_ALU(8, uint8_t, int8_t)
X86_ALU(16, uint16_t, int16_t)
X86_ALU(32, uint32_t, int32_t)
X86_RC(8, uint8_t)
X86_RC(16, uint16_t)
X86_RC(32, uint32_t)

/* imul with truncation flags (two/three-operand forms). */
static inline uint32_t imul32(Flags *f, uint32_t a, uint32_t b) {
    int64_t w = (int64_t)(int32_t)a * (int32_t)b; int32_t r = (int32_t)w;
    f->cf = f->of = w != r; return (uint32_t)r;
}
static inline uint32_t imul16(Flags *f, uint32_t a, uint32_t b) {
    int32_t w = (int32_t)(int16_t)a * (int16_t)b; int16_t r = (int16_t)w;
    f->cf = f->of = w != r; return (uint16_t)r;
}

/* ---- x87 (lift.py FPU = True) ---------------------------------------------
 * Registers are doubles, not 80-bit extended: enough for game arithmetic.
 * Exceptions stay masked (results are inf/NaN like a masked 387); the status
 * word keeps C0-C3, TOP is kept apart in ftop. */
#define FST(c, i) ((c)->st[((c)->ftop + (uint32_t)(i)) & 7])
static inline void fpush(Cpu *c, double v) { c->ftop = (c->ftop - 1) & 7; c->st[c->ftop] = v; }
static inline void fpop(Cpu *c) { c->ftop = (c->ftop + 1) & 7; }
static inline void x86_fninit(Cpu *c) { c->fcw = 0x037F; c->fsw = 0; c->ftop = 0; }
static inline uint32_t x86_fstsw(Cpu *c) { return (c->fsw & ~0x3800u) | (c->ftop & 7) << 11; }
/* compare: C3 C2 C0 = 000 greater, 001 less, 100 equal, 111 unordered */
static inline void fcom(Cpu *c, double a, double b) {
    c->fsw &= (uint16_t)~0x4500u;
    if (a != a || b != b) c->fsw |= 0x4500;
    else if (a < b) c->fsw |= 0x0100;
    else if (a == b) c->fsw |= 0x4000;
}
static inline void fxam(Cpu *c, double v) {
    c->fsw &= (uint16_t)~0x4700u;
    if (signbit(v)) c->fsw |= 0x0200;
    switch (fpclassify(v)) {
    case FP_NAN: c->fsw |= 0x0100; break;
    case FP_INFINITE: c->fsw |= 0x0500; break;
    case FP_ZERO: c->fsw |= 0x4000; break;
    case FP_SUBNORMAL: c->fsw |= 0x4400; break;
    default: c->fsw |= 0x0400; break;
    }
}
static inline double fround(Cpu *c, double v) {      /* by the control word's rounding mode */
    switch (c->fcw >> 10 & 3) {
    case 0: { double r = floor(v + 0.5); return (r - v == 0.5 && fmod(r, 2.0) != 0) ? r - 1 : r; }
    case 1: return floor(v);
    case 2: return ceil(v);
    default: return trunc(v);
    }
}
static inline uint32_t fist16(Cpu *c, double v) {
    double r = fround(c, v);
    return r >= -32768.0 && r < 32768.0 ? (uint32_t)(uint16_t)(int16_t)r : 0x8000u;
}
static inline uint32_t fist32(Cpu *c, double v) {
    double r = fround(c, v);
    return r >= -2147483648.0 && r < 2147483648.0 ? (uint32_t)(int32_t)r : 0x80000000u;
}
static inline uint64_t fist64(Cpu *c, double v) {
    double r = fround(c, v);
    return r >= -9223372036854775808.0 && r < 9223372036854775808.0 ? (uint64_t)(int64_t)r : 0x8000000000000000ull;
}
static inline double rdf32(Cpu *c, uint32_t a) { uint32_t v = rd32(c, a); float f; memcpy(&f, &v, 4); return f; }
static inline double rdf64(Cpu *c, uint32_t a) {
    uint64_t v = rd32(c, a) | (uint64_t)rd32(c, a + 4) << 32; double d; memcpy(&d, &v, 8); return d;
}
static inline void wrf32(Cpu *c, uint32_t a, double d) { float f = (float)d; uint32_t v; memcpy(&v, &f, 4); wr32(c, a, v); }
static inline void wrf64(Cpu *c, uint32_t a, double d) {
    uint64_t v; memcpy(&v, &d, 8); wr32(c, a, (uint32_t)v); wr32(c, a + 4, (uint32_t)(v >> 32));
}
static inline uint64_t rd64(Cpu *c, uint32_t a) { return rd32(c, a) | (uint64_t)rd32(c, a + 4) << 32; }
static inline void wr64(Cpu *c, uint32_t a, uint64_t v) { wr32(c, a, (uint32_t)v); wr32(c, a + 4, (uint32_t)(v >> 32)); }
/* 80-bit extended <-> double */
static inline double rdf80(Cpu *c, uint32_t a) {
    uint64_t m = rd64(c, a);
    uint32_t se = rd16(c, a + 8);
    int e = (int)(se & 0x7FFF);
    double d;
    if (e == 0x7FFF) d = (m << 1) ? NAN : INFINITY;
    else d = ldexp((double)m, e - 16383 - 63);
    return (se & 0x8000) ? -d : d;
}
static inline void wrf80(Cpu *c, uint32_t a, double d) {
    uint32_t se = signbit(d) ? 0x8000u : 0;
    uint64_t m = 0;
    d = fabs(d);
    if (d != d) { se |= 0x7FFF; m = 0xC000000000000000ull; }
    else if (isinf(d)) { se |= 0x7FFF; m = 0x8000000000000000ull; }
    else if (d != 0) {
        int e;
        double fr = frexp(d, &e);                      /* d = fr * 2^e, fr in [0.5, 1) */
        m = (uint64_t)ldexp(fr, 64);
        se |= (uint32_t)(e - 1 + 16383) & 0x7FFF;
    }
    wr64(c, a, m);
    wr16(c, a + 8, se);
}
/* fnsave / frstor, 32-bit protected-mode layout: 28-byte environment, then ST(0..7) */
static inline void x86_fnsave(Cpu *c, uint32_t a) {
    wr32(c, a, c->fcw); wr32(c, a + 4, x86_fstsw(c)); wr32(c, a + 8, 0);
    for (uint32_t k = 12; k < 28; k += 4) wr32(c, a + k, 0);
    for (int i = 0; i < 8; i++) wrf80(c, a + 28 + 10 * (uint32_t)i, FST(c, i));
    x86_fninit(c);
}
static inline void x86_frstor(Cpu *c, uint32_t a) {
    c->fcw = (uint16_t)rd32(c, a);
    uint32_t sw = rd32(c, a + 4);
    c->fsw = (uint16_t)(sw & ~0x3800u);
    c->ftop = sw >> 11 & 7;
    for (int i = 0; i < 8; i++) FST(c, i) = rdf80(c, a + 28 + 10 * (uint32_t)i);
}
static inline void x86_fnstenv(Cpu *c, uint32_t a) {
    wr32(c, a, c->fcw); wr32(c, a + 4, x86_fstsw(c)); wr32(c, a + 8, 0);
    for (uint32_t k = 12; k < 28; k += 4) wr32(c, a + k, 0);
}
static inline void x86_fldenv(Cpu *c, uint32_t a) {
    c->fcw = (uint16_t)rd32(c, a);
    uint32_t sw = rd32(c, a + 4);
    c->fsw = (uint16_t)(sw & ~0x3800u);
    c->ftop = sw >> 11 & 7;
}

#endif
