#!/usr/bin/env python3
"""Instruction-level check of lift.py's x87 translation against Unicorn.

Every case runs

    fninit; fld qword [A]; fld qword [B]; <instruction>; fnstsw [SW]; fstp qword [OUT + 8k] ...

once on Unicorn and once lifted (FPU = True), compiled against runtime/x86.h
and run natively.  The popped registers, TOP and the condition codes, and
whatever the instruction wrote to its memory operand must match.  Registers
are doubles in x86.h, so values are compared as the qwords both sides store;
transcendental results may differ in the last bits (80-bit vs double) and are
compared with a relative tolerance.  C1 is compared only where the runtime
defines it (fxam, fprem): the 387 also sets it for "rounded up".  A zero
remainder from fprem/fprem1 keeps the dividend's sign as the SDM says, where
Unicorn returns +0, so the sign of zero is not compared there.

Usage: x87test.py [--cc clang]
"""
from __future__ import annotations

import argparse
import math
import pathlib
import struct
import subprocess
import sys
import tempfile

import capstone
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc

import disasm
import lift

ROOT = pathlib.Path(__file__).resolve().parents[1]
CODE, A, B, M, SW, OUT = 0x1000, 0x2000, 0x2008, 0x2100, 0x2200, 0x2300
MEM_SIZE = 0x10000
ALL = 0x4500 | 0x3800        # C3 C2 C0 and TOP
WITH_C1 = ALL | 0x0200


def d32(a: int) -> bytes:
    return struct.pack("<I", a)


def mem(op: int, reg: int, addr: int = M) -> bytes:
    return bytes([op, reg << 3 | 5]) + d32(addr)


def reg(op: int, r: int, i: int = 1) -> bytes:
    return bytes([op, 0xC0 | r << 3 | i])


def f80(x: float) -> bytes:
    """80-bit extended encoding of a double (exact)."""
    if x == 0:
        return bytes(8) + struct.pack("<H", 0x8000 if math.copysign(1, x) < 0 else 0)
    m, e = math.frexp(abs(x))
    return struct.pack("<QH", int(m * 2 ** 64), (e - 1 + 16383) | (0x8000 if x < 0 else 0))


PAIRS = [(1.5, 2.25), (-3.0, 0.5), (2.5, -2.5), (7.0, 7.0), (1e10, 3.0), (0.75, -6.5)]
SMALL = [(0.25, 0.5), (-0.5, 0.75), (0.125, -0.375)]           # f2xm1, fyl2xp1, trig
POSITIVE = [(1.5, 2.25), (3.0, 0.5), (10.0, 7.0)]              # logarithms, sqrt
MEMVALS = [2.0, -1.25, 3.5]

ARITH_NAMES = ["add", "mul", "com", "comp", "sub", "subr", "div", "divr"]


def cases():
    """(name, instruction bytes, stack delta, memory operand bytes per value, pairs, tolerance, status mask)
    A tolerance of -1 compares exactly but treats +0 and -0 as equal."""
    fmt = {0xD8: ("<f", float), 0xDC: ("<d", float), 0xDA: ("<i", int), 0xDE: ("<h", int)}
    for op, (f, conv) in fmt.items():
        for r, n in enumerate(ARITH_NAMES):
            yield (f"{op:02X} /{r} f{n} m", mem(op, r), -1 if r == 3 else 0,
                   [struct.pack(f, conv(v)) for v in MEMVALS], PAIRS, 0, ALL)
    for op, delta in ((0xD8, 0), (0xDC, 0), (0xDE, -1)):
        for r, n in enumerate(ARITH_NAMES):
            if op != 0xD8 and r in (2, 3):
                continue
            yield (f"{op:02X} {0xC1 | r << 3:02X} f{n}{'p' if op == 0xDE else ''} st", reg(op, r),
                   delta - (1 if op == 0xD8 and r == 3 else 0), [b""], PAIRS, 0, ALL)
    yield ("DE D9 fcompp", b"\xde\xd9", -2, [b""], PAIRS, 0, ALL)
    yield ("DA E9 fucompp", b"\xda\xe9", -2, [b""], PAIRS, 0, ALL)
    yield ("D9 C1 fld st(1)", b"\xd9\xc1", 1, [b""], PAIRS, 0, ALL)
    yield ("D9 C9 fxch", b"\xd9\xc9", 0, [b""], PAIRS, 0, ALL)
    yield ("DD D1 fst st(1)", b"\xdd\xd1", 0, [b""], PAIRS, 0, ALL)
    yield ("DD D9 fstp st(1)", b"\xdd\xd9", -1, [b""], PAIRS, 0, ALL)
    yield ("DD E1 fucom", b"\xdd\xe1", 0, [b""], PAIRS, 0, ALL)
    yield ("DD E9 fucomp", b"\xdd\xe9", -1, [b""], PAIRS, 0, ALL)
    simple = {0xE0: ("fchs", 0, PAIRS), 0xE1: ("fabs", 0, PAIRS), 0xE4: ("ftst", 0, PAIRS),
              0xE8: ("fld1", 1, PAIRS), 0xE9: ("fldl2t", 1, PAIRS), 0xEA: ("fldl2e", 1, PAIRS),
              0xEB: ("fldpi", 1, PAIRS), 0xEC: ("fldlg2", 1, PAIRS), 0xED: ("fldln2", 1, PAIRS),
              0xEE: ("fldz", 1, PAIRS), 0xFC: ("frndint", 0, PAIRS), 0xFD: ("fscale", 0, PAIRS),
              0xFA: ("fsqrt", 0, POSITIVE), 0xF4: ("fxtract", 1, PAIRS), 0xF8: ("fprem", 0, PAIRS),
              0xF5: ("fprem1", 0, PAIRS)}
    for b2, (n, delta, pairs) in simple.items():
        rem = n in ("fprem", "fprem1")
        yield (f"D9 {b2:02X} {n}", bytes([0xD9, b2]), delta, [b""], pairs, -1 if rem else 0,
               WITH_C1 if rem else ALL)
    yield ("D9 E5 fxam", b"\xd9\xe5", 0, [b""], PAIRS, 0, WITH_C1)
    trans = {0xF0: ("f2xm1", 0, SMALL), 0xF1: ("fyl2x", -1, POSITIVE), 0xF2: ("fptan", 1, SMALL),
             0xF3: ("fpatan", -1, PAIRS), 0xF9: ("fyl2xp1", -1, SMALL), 0xFB: ("fsincos", 1, SMALL),
             0xFE: ("fsin", 0, SMALL), 0xFF: ("fcos", 0, SMALL)}
    for b2, (n, delta, pairs) in trans.items():
        yield (f"D9 {b2:02X} {n}", bytes([0xD9, b2]), delta, [b""], pairs, 1e-12, ALL)
    stores = [("D9 /2 fst m32", mem(0xD9, 2), 0), ("D9 /3 fstp m32", mem(0xD9, 3), -1),
              ("DD /2 fst m64", mem(0xDD, 2), 0), ("DD /3 fstp m64", mem(0xDD, 3), -1),
              ("DB /2 fist m32", mem(0xDB, 2), 0), ("DB /3 fistp m32", mem(0xDB, 3), -1),
              ("DF /2 fist m16", mem(0xDF, 2), 0), ("DF /3 fistp m16", mem(0xDF, 3), -1),
              ("DF /7 fistp m64", mem(0xDF, 7), -1), ("DB /7 fstp m80", mem(0xDB, 7), -1),
              ("D9 /7 fnstcw", mem(0xD9, 7), 0), ("DD /7 fnstsw m16", mem(0xDD, 7), 0)]
    for n, code, delta in stores:
        yield (n, code, delta, [b""], PAIRS + [(0.0, 1e6), (0.0, -40000.0)], 0, ALL)
    loads = [("D9 /0 fld m32", mem(0xD9, 0), "<f", float), ("DD /0 fld m64", mem(0xDD, 0), "<d", float),
             ("DB /0 fild m32", mem(0xDB, 0), "<i", int), ("DF /0 fild m16", mem(0xDF, 0), "<h", int),
             ("DF /5 fild m64", mem(0xDF, 5), "<q", int)]
    for n, code, f, conv in loads:
        yield (n, code, 1, [struct.pack(f, conv(v)) for v in MEMVALS], PAIRS[:2], 0, ALL)
    yield ("DB /5 fld m80", mem(0xDB, 5), 1, [f80(v) for v in MEMVALS + [1e-5, -123456.75]], PAIRS[:2], 0, ALL)
    for rc in range(4):                          # rounding modes: fldcw [M]; fistp dword [M+8] / frndint
        cw = struct.pack("<H", 0x037F | rc << 10)
        yield (f"fldcw rc={rc}; fistp m32", mem(0xD9, 5) + mem(0xDB, 3, M + 8), -1, [cw], PAIRS, 0, ALL)
        yield (f"fldcw rc={rc}; frndint", mem(0xD9, 5) + b"\xd9\xfc", 0, [cw], PAIRS, 0, ALL)
    yield ("DF E0 fnstsw ax; mov [M], ax", b"\xd8\xd9" + b"\xdf\xe0" + b"\x66\xa3" + d32(M), -1,
           [b""], PAIRS, 0, ALL)


def program(insn: bytes, depth: int) -> bytes:
    code = b"\xdb\xe3" + mem(0xDD, 0, A) + mem(0xDD, 0, B) + insn + mem(0xDD, 7, SW)
    for k in range(depth):
        code += mem(0xDD, 3, OUT + 8 * k)
    return code


def memory(a: float, b: float, operand: bytes) -> bytes:
    m = bytearray(MEM_SIZE)
    m[A:A + 8] = struct.pack("<d", a)
    m[B:B + 8] = struct.pack("<d", b)
    m[M:M + len(operand)] = operand
    return bytes(m)


def run_unicorn(code: bytes, init: bytes) -> bytes:
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0, MEM_SIZE)
    uc.mem_write(0, init)
    uc.mem_write(CODE, code)
    uc.emu_start(CODE, CODE + len(code))
    return bytes(uc.mem_read(0, MEM_SIZE))


def lift_c(code: bytes, fname: str) -> str:
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    em = lift.Emitter(lift.Func(CODE), None, whole=True)
    body = []
    for ci in cs.disasm(code, CODE):
        i = disasm.Insn(ci.address, ci.size, ci.id, ci.mnemonic, ci.op_str, list(ci.operands),
                        bytes(ci.bytes), list(ci.prefix))
        em.cur = i
        body += [f"/* {ci.mnemonic} {ci.op_str} */", *em.lift(i)]
    return (f"static void {fname}(Cpu *c) {{\n"
            "    uint32_t eax = 0, ecx = 0, edx = 0, ebx = 0, esp = 0x8000, ebp = 0, esi = 0, edi = 0;\n"
            "    Flags f = {0};\n    " + "\n    ".join(body) +
            "\n    (void)eax; (void)ecx; (void)edx; (void)ebx; (void)esp; (void)ebp; (void)esi; (void)edi; (void)f;\n}\n")


def same_double(x: bytes, y: bytes, tol: float) -> bool:
    if x == y:
        return True
    a, b = struct.unpack("<d", x)[0], struct.unpack("<d", y)[0]
    if math.isnan(a) and math.isnan(b):
        return True
    if tol < 0:
        return a == b
    return tol > 0 and math.isfinite(a) and math.isfinite(b) and abs(a - b) <= tol * max(1.0, abs(a))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cc", default="clang")
    args = ap.parse_args()
    lift.FPU = True

    runs = []                    # (case, a, b, operand, code, depth)
    funcs, calls = [], []
    for k, (name, insn, delta, operands, pairs, tol, mask) in enumerate(cases()):
        depth = 2 + delta
        code = program(insn, depth)
        funcs.append(lift_c(code, f"case_{k}"))
        for operand in operands:
            for a, b in pairs:
                n = len(runs)
                runs.append((name, a, b, operand, code, depth, tol, mask))
                init = ", ".join(str(x) for x in (struct.pack("<dd", a, b)))
                op = ", ".join(str(x) for x in operand) or "0"
                calls.append(f"    {{ static const uint8_t ab[16] = {{{init}}}, op[] = {{{op}}};\n"
                             f"      run({n}, case_{k}, ab, op, {len(operand)}); }}")
    src = ('#include <stdio.h>\n#include <stdlib.h>\n#include "x86.h"\n\n' + "\n".join(funcs) + f"""
static void run(int n, void (*fn)(Cpu *), const uint8_t *ab, const uint8_t *op, unsigned oplen) {{
    static Cpu c;
    memset(&c, 0, sizeof c);
    c.mem = calloc(1, {MEM_SIZE});
    c.mem_size = {MEM_SIZE};
    c.budget = 1000;
    memcpy(c.mem + {A}, ab, 16);
    memcpy(c.mem + {M}, op, oplen);
    if (setjmp(c.stop) == 0) fn(&c);
    printf("%d", n);
    for (unsigned k = 0; k < 64; k++) printf(" %02x", c.mem[{OUT} + k]);
    printf(" |");
    for (unsigned k = 0; k < 2; k++) printf(" %02x", c.mem[{SW} + k]);
    printf(" |");
    for (unsigned k = 0; k < 16; k++) printf(" %02x", c.mem[{M} + k]);
    printf("\\n");
    free(c.mem);
}}

int main(void) {{
{chr(10).join(calls)}
    return 0;
}}
""")
    with tempfile.TemporaryDirectory() as tmp:
        c_path, exe = pathlib.Path(tmp) / "x87.c", pathlib.Path(tmp) / "x87"
        c_path.write_text(src)
        subprocess.run([args.cc, "-O1", "-I", str(ROOT / "runtime"), str(c_path), "-o", str(exe), "-lm"], check=True)
        native = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout.splitlines()

    failed = 0
    for line, (name, a, b, operand, code, depth, tol, mask) in zip(native, runs):
        out_hex, sw_hex, m_hex = line.split(" |")
        got_out = bytes.fromhex("".join(out_hex.split()[1:]))
        got_sw = struct.unpack("<H", bytes.fromhex("".join(sw_hex.split())))[0]
        got_m = bytes.fromhex("".join(m_hex.split()))
        ref = run_unicorn(code, memory(a, b, operand))
        want_out, want_m = ref[OUT:OUT + 64], ref[M:M + 16]
        want_sw = struct.unpack_from("<H", ref, SW)[0]
        problems = []
        for k in range(depth):
            if not same_double(got_out[8 * k:8 * k + 8], want_out[8 * k:8 * k + 8], tol):
                problems.append(f"ST({k}) {struct.unpack_from('<d', got_out, 8 * k)[0]!r} "
                                f"want {struct.unpack_from('<d', want_out, 8 * k)[0]!r}")
        if (got_sw ^ want_sw) & mask:
            problems.append(f"status {got_sw:04x} want {want_sw:04x}")
        if got_m != want_m:
            problems.append(f"memory {got_m.hex()} want {want_m.hex()}")
        if problems:
            failed += 1
            if failed <= 40:
                print(f"FAIL {name} a={a!r} b={b!r} op={operand.hex()}: {'; '.join(problems)}")
    print(f"{len(runs)} runs, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
