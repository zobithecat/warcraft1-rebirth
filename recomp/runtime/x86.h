/* Runtime support for C lifted from 32-bit x86 (Watcom/DOS4GW flat model).
 *
 * Guest memory is one flat byte array; guest address == offset into it,
 * matching DOS/4GW's zero-based flat selectors.  Out-of-range accesses and
 * runaway loops longjmp back to the caller of the lifted entry point.
 */
#ifndef RECOMP_X86_H
#define RECOMP_X86_H

#include <setjmp.h>
#include <stdint.h>
#include <string.h>

enum { EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI };   /* x86 register encoding order */

/* STOP_BADRET: a `ret` popped something other than its caller's return address. */
enum { STOP_OK = 0, STOP_FAULT = 1, STOP_BUDGET = 2, STOP_DIVIDE = 3, STOP_BADRET = 4 };

typedef struct Cpu {
    uint32_t r[8];
    uint8_t *mem;
    uint32_t mem_size;
    int64_t budget;        /* decremented at every backward branch */
    jmp_buf stop;
    uint32_t fault_addr;
    uint32_t ro_lo, ro_hi;  /* guest code: writes here fault (no self-modifying game code) */
    uint32_t ret_to;        /* return address popped by the last `ret` */
} Cpu;

typedef struct Flags {
    uint8_t cf, zf, sf, of, pf;
} Flags;

static inline void x86_stop(Cpu *c, int why, uint32_t addr) {
    c->fault_addr = addr;
    longjmp(c->stop, why);
}

static inline uint8_t *x86_ptr(Cpu *c, uint32_t a, uint32_t n) {
    if (a > c->mem_size || c->mem_size - a < n) x86_stop(c, STOP_FAULT, a);
    return c->mem + a;
}

static inline uint32_t rd8(Cpu *c, uint32_t a) { return *x86_ptr(c, a, 1); }
static inline uint32_t rd16(Cpu *c, uint32_t a) { uint16_t v; memcpy(&v, x86_ptr(c, a, 2), 2); return v; }
static inline uint32_t rd32(Cpu *c, uint32_t a) { uint32_t v; memcpy(&v, x86_ptr(c, a, 4), 4); return v; }
static inline uint8_t *x86_wptr(Cpu *c, uint32_t a, uint32_t n) {
    if (a < c->ro_hi && a + n > c->ro_lo) x86_stop(c, STOP_FAULT, a);
    return x86_ptr(c, a, n);
}
static inline void wr8(Cpu *c, uint32_t a, uint32_t v) { *x86_wptr(c, a, 1) = (uint8_t)v; }
static inline void wr16(Cpu *c, uint32_t a, uint32_t v) { uint16_t x = (uint16_t)v; memcpy(x86_wptr(c, a, 2), &x, 2); }
static inline void wr32(Cpu *c, uint32_t a, uint32_t v) { memcpy(x86_wptr(c, a, 4), &v, 4); }

static inline void x86_tick(Cpu *c, uint32_t at) {
    if (--c->budget < 0) x86_stop(c, STOP_BUDGET, at);
}

static inline uint8_t parity8(uint32_t v) { return !__builtin_parity(v & 0xFF); }

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

X86_ALU(8, uint8_t, int8_t)
X86_ALU(16, uint16_t, int16_t)
X86_ALU(32, uint32_t, int32_t)

/* imul with truncation flags (two/three-operand forms). */
static inline uint32_t imul32(Flags *f, uint32_t a, uint32_t b) {
    int64_t w = (int64_t)(int32_t)a * (int32_t)b; int32_t r = (int32_t)w;
    f->cf = f->of = w != r; return (uint32_t)r;
}
static inline uint32_t imul16(Flags *f, uint32_t a, uint32_t b) {
    int32_t w = (int32_t)(int16_t)a * (int16_t)b; int16_t r = (int16_t)w;
    f->cf = f->of = w != r; return (uint16_t)r;
}

#endif
