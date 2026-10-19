#!/usr/bin/env python3
"""Instruction-level check of the x86.h ALU helpers against Unicorn.

For every (operation, width) the real instruction runs on Unicorn as
`op eax/ax/al, ecx/cx/cl` with random operands and random incoming flags; the
result and every flag the architecture defines for that case must match the
helper's.  Flags an instruction must leave alone (CF for inc/dec, ZF/SF/PF
for rotates, everything for a zero shift count) are checked too.

Usage: alutest.py [--cases N] [--lib build/libalu.dylib]
"""
from __future__ import annotations

import argparse
import ctypes
import pathlib
import random
import sys

from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn import x86_const as U

ROOT = pathlib.Path(__file__).resolve().parents[1]
CF, PF, ZF, SF, OF = 0x001, 0x004, 0x040, 0x080, 0x800
ARITH = CF | PF | ZF | SF | OF
CODE = 0x1000

# name: (op id in alu_test.c, opcode bytes for "op eax, ecx" at 32 bits, 8-bit opcode, flags defined)
OPS = {
    "add": (0, b"\x01\xc8", b"\x00\xc8", ARITH), "adc": (1, b"\x11\xc8", b"\x10\xc8", ARITH),
    "sub": (2, b"\x29\xc8", b"\x28\xc8", ARITH), "sbb": (3, b"\x19\xc8", b"\x18\xc8", ARITH),
    "and": (4, b"\x21\xc8", b"\x20\xc8", ARITH), "or": (5, b"\x09\xc8", b"\x08\xc8", ARITH),
    "xor": (6, b"\x31\xc8", b"\x30\xc8", ARITH),
    "inc": (7, b"\xff\xc0", b"\xfe\xc0", ARITH), "dec": (8, b"\xff\xc8", b"\xfe\xc8", ARITH),
    "neg": (9, b"\xf7\xd8", b"\xf6\xd8", ARITH),
    "shl": (10, b"\xd3\xe0", b"\xd2\xe0", None), "shr": (11, b"\xd3\xe8", b"\xd2\xe8", None),
    "sar": (12, b"\xd3\xf8", b"\xd2\xf8", None), "rol": (13, b"\xd3\xc0", b"\xd2\xc0", None),
    "ror": (14, b"\xd3\xc8", b"\xd2\xc8", None),
    "imul": (15, b"\x0f\xaf\xc1", None, CF | OF),
}
EDGE = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


def defined_flags(name: str, bits: int, count: int) -> int:
    """Flags the architecture defines after `name` with this shift/rotate count."""
    spec = OPS[name][3]
    if spec is not None:
        return spec
    n = count & 31
    if n == 0:
        return ARITH                     # all unchanged
    if name in ("rol", "ror"):
        return CF | PF | ZF | SF | (OF if n == 1 else 0)    # ZF/SF/PF must be unchanged
    m = CF | PF | ZF | SF | (OF if n == 1 else 0)
    if bits < 32 and name in ("shl", "shr") and n > bits:
        m &= ~CF                         # undefined for counts past the operand width
    return m


def encode(name: str, bits: int) -> bytes:
    _, op32, op8, _ = OPS[name]
    if bits == 32:
        return op32
    if bits == 16:
        return b"\x66" + op32
    return op8


def run_unicorn(uc: Uc, code: bytes, a: int, b: int, flags: int) -> tuple[int, int]:
    uc.mem_write(CODE, code + b"\xf4")
    uc.reg_write(U.UC_X86_REG_EAX, a)
    uc.reg_write(U.UC_X86_REG_ECX, b)
    uc.reg_write(U.UC_X86_REG_EFLAGS, 0x2 | flags)
    uc.emu_start(CODE, CODE + len(code))
    return uc.reg_read(U.UC_X86_REG_EAX), uc.reg_read(U.UC_X86_REG_EFLAGS)


def operand(rng: random.Random, bits: int) -> int:
    v = rng.choice(EDGE) if rng.random() < 0.3 else rng.getrandbits(32)
    return v & ((1 << bits) - 1) | (rng.getrandbits(32) & ~((1 << bits) - 1) & 0xFFFFFFFF)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--lib", default=str(ROOT / "build" / "libalu.dylib"))
    args = ap.parse_args()

    lib = ctypes.CDLL(args.lib)
    lib.alu.restype = ctypes.c_uint32
    lib.alu.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32,
                        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0, 0x10000)
    rng = random.Random(args.seed)
    bad_total = 0

    for name, (opid, _, op8, _) in OPS.items():
        for bits in (8, 16, 32):
            if bits == 8 and op8 is None:
                continue
            code = encode(name, bits)
            mask = (1 << bits) - 1
            bad, example = 0, None
            for _ in range(args.cases):
                a = operand(rng, bits)
                b = operand(rng, bits) if name not in ("shl", "shr", "sar", "rol", "ror") else \
                    rng.choice([0, 1, 2, bits - 1, bits, bits + 1, 31, 32, rng.randrange(256)])
                fin = rng.getrandbits(12) & ARITH
                want_r, want_f = run_unicorn(uc, code, a, b, fin)
                out = ctypes.c_uint32()
                got_r = lib.alu(opid, bits, a, b, fin, ctypes.byref(out))
                defined = defined_flags(name, bits, b)
                # The helper returns the narrow result; the register keeps its upper bits.
                ok = (want_r & mask) == (got_r & mask) and (want_f & defined) == (out.value & defined)
                if not ok:
                    bad += 1
                    if example is None:
                        example = (f"a={a:#x} b={b:#x} flags_in={fin:#x}: x86 r={want_r & mask:#x} "
                                   f"f={want_f & defined:#x} / helper r={got_r & mask:#x} f={out.value & defined:#x}")
            bad_total += bad
            print(f"{'PASS' if not bad else 'FAIL'} {name}{bits}: {args.cases - bad}/{args.cases}"
                  + (f"  e.g. {example}" if example else ""))
    print(f"{bad_total} mismatching cases")
    sys.exit(1 if bad_total else 0)


if __name__ == "__main__":
    main()
