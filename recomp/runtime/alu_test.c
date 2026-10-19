/* Exports the x86.h ALU helpers for instruction-level tests (tools/alutest.py). */
#include "x86.h"

enum { OP_ADD, OP_ADC, OP_SUB, OP_SBB, OP_AND, OP_OR, OP_XOR, OP_INC, OP_DEC, OP_NEG,
       OP_SHL, OP_SHR, OP_SAR, OP_ROL, OP_ROR, OP_IMUL };

#define EF_CF 0x001u
#define EF_PF 0x004u
#define EF_ZF 0x040u
#define EF_SF 0x080u
#define EF_OF 0x800u

static uint32_t pack(const Flags *f) {
    return (f->cf ? EF_CF : 0) | (f->pf ? EF_PF : 0) | (f->zf ? EF_ZF : 0) |
           (f->sf ? EF_SF : 0) | (f->of ? EF_OF : 0);
}

#define DISPATCH(BITS)                                                              \
    switch (op) {                                                                   \
    case OP_ADD: r = add##BITS(&f, a, b, 0); break;                                 \
    case OP_ADC: r = add##BITS(&f, a, b, f.cf); break;                              \
    case OP_SUB: r = sub##BITS(&f, a, b, 0); break;                                 \
    case OP_SBB: r = sub##BITS(&f, a, b, f.cf); break;                              \
    case OP_AND: r = logic##BITS(&f, a & b); break;                                 \
    case OP_OR:  r = logic##BITS(&f, a | b); break;                                 \
    case OP_XOR: r = logic##BITS(&f, a ^ b); break;                                 \
    case OP_INC: r = inc##BITS(&f, a); break;                                       \
    case OP_DEC: r = dec##BITS(&f, a); break;                                       \
    case OP_NEG: r = neg##BITS(&f, a); break;                                       \
    case OP_SHL: r = shl##BITS(&f, a, b); break;                                    \
    case OP_SHR: r = shr##BITS(&f, a, b); break;                                    \
    case OP_SAR: r = sar##BITS(&f, a, b); break;                                    \
    case OP_ROL: r = rol##BITS(&f, a, b); break;                                    \
    case OP_ROR: r = ror##BITS(&f, a, b); break;                                    \
    default: return 0xDEADBEEF;                                                     \
    }

/* Applies `op` at `bits` width to (a, b) starting from eflags `in`; returns the
 * result and stores the resulting CF/PF/ZF/SF/OF bits in *out. */
uint32_t alu(int op, int bits, uint32_t a, uint32_t b, uint32_t in, uint32_t *out) {
    Flags f = { !!(in & EF_CF), !!(in & EF_ZF), !!(in & EF_SF), !!(in & EF_OF), !!(in & EF_PF) };
    uint32_t r = 0;
    if (op == OP_IMUL) {
        if (bits == 32) r = imul32(&f, a, b);
        else if (bits == 16) r = imul16(&f, a, b);
        else return 0xDEADBEEF;
    } else if (bits == 8) {
        DISPATCH(8)
    } else if (bits == 16) {
        DISPATCH(16)
    } else {
        DISPATCH(32)
    }
    *out = pack(&f);
    return r;
}
