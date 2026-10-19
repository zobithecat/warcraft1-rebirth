#!/usr/bin/env python3
"""Differential test: lifted C (arm64 dylib) vs the original x86 code (Unicorn).

Both sides start from the same guest memory (war.exe loaded at its preferred
addresses, plus a scratch area) and the same registers, run one function until
it returns, and must end with identical registers and identical memory.

Inputs are fuzzed where they matter: a first pass records which global
addresses the function reads, and later cases put small ints, boundary values,
random words or valid pointers into those globals and into the registers.

Usage: difftest.py [--cases N] [--seed S] [--lib build/liblifted.dylib] [ADDR ...]
"""
from __future__ import annotations

import argparse
import ctypes
import pathlib
import random
import sys
from dataclasses import dataclass

from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_MODE_32, UC_PROT_EXEC, UC_PROT_READ,
                     Uc, UcError)
from unicorn import x86_const as U

import disasm
import lift
from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]
MEM_SIZE = 0x200000
SCRATCH = (0x100000, 0x1E0000)
STACK_TOP = 0x1F0000
SENTINEL = 0x1FFF00          # return address; holds `hlt` on the Unicorn side
# Both sides stop after the same number of backward branches (a jump to an
# address <= the jumping instruction), which is what x86_tick() counts in C.
BRANCH_BUDGET = 20_000
GPR_UC = [U.UC_X86_REG_EAX, U.UC_X86_REG_ECX, U.UC_X86_REG_EDX, U.UC_X86_REG_EBX,
          U.UC_X86_REG_ESP, U.UC_X86_REG_EBP, U.UC_X86_REG_ESI, U.UC_X86_REG_EDI]
NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
STOP = {0: "ok", 1: "fault", 2: "budget", 3: "divide", 4: "badret"}
BOUNDARY = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000,
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE]


@dataclass
class Outcome:
    status: str
    regs: list[int]
    mem: bytes
    fault: int = 0


def base_memory(mod: LEModule) -> bytearray:
    mem = bytearray(MEM_SIZE)
    for o in mod.objects:
        mem[o.base:o.base + len(o.data)] = o.data
    mem[SENTINEL] = 0xF4   # hlt
    return mem


class Lifted:
    def __init__(self, path: pathlib.Path, code: tuple[int, int]):
        self.code = code
        self.lib = ctypes.CDLL(str(path))
        self.lib.lifted_run.restype = ctypes.c_int
        self.lib.lifted_run.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p,
                                        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int64,
                                        ctypes.POINTER(ctypes.c_uint32)]
        self.addrs = [self.lib.lifted_addr(i) for i in range(self.lib.lifted_count())]

    def run(self, addr: int, regs: list[int], mem: bytearray) -> Outcome:
        r = (ctypes.c_uint32 * 8)(*regs)
        buf = ctypes.create_string_buffer(bytes(mem), len(mem))
        fault = ctypes.c_uint32(0)
        why = self.lib.lifted_run(addr, r, buf, len(mem), *self.code, BRANCH_BUDGET, ctypes.byref(fault))
        if why < 0:
            raise KeyError(f"{addr:#x} not in lifted table")
        return Outcome(STOP[why], list(r), buf.raw[:len(mem)], fault.value)


class Reference:
    def __init__(self, code: tuple[int, int], base: bytearray):
        # Game code never writes its own code object; make that a fault so a
        # stray pointer can't patch code (and leave stale translations behind).
        self.code = code
        self.allowed: set[int] = set()   # instruction addresses of the lifted code under test
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(0, MEM_SIZE)
        self.uc.mem_write(code[0], bytes(base[code[0]:code[1]]))   # once; run() skips this range
        self.uc.mem_protect(code[0], code[1] - code[0], UC_PROT_READ | UC_PROT_EXEC)
        self.reads: set[int] = set()
        self.executed: set[int] = set()
        self.uc.hook_add(UC_HOOK_MEM_READ, self._on_read)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)

    def _on_code(self, uc, addr, size, data):
        if addr not in self.allowed and addr != SENTINEL:
            self.left_body = addr        # returned somewhere other than the caller
            uc.emu_stop()
            return
        self.executed.add(addr)
        if addr <= self.prev:
            self.back += 1
            if self.back > BRANCH_BUDGET:
                self.over_budget = True
                uc.emu_stop()
        self.prev = addr

    def _on_read(self, uc, access, addr, size, value, data):
        self.reads.add(addr)

    def run(self, addr: int, regs: list[int], mem: bytearray) -> Outcome:
        uc = self.uc
        lo, hi = self.code       # code bytes never change, so leave them mapped as-is
        uc.mem_write(0, bytes(mem[:lo]))
        uc.mem_write(hi, bytes(mem[hi:]))
        for reg, v in zip(GPR_UC, regs):
            uc.reg_write(reg, v)
        uc.reg_write(U.UC_X86_REG_EFLAGS, 0x2)
        self.reads.clear()
        self.prev, self.back, self.over_budget, self.left_body = -1, 0, False, None
        status, fault = "ok", 0
        try:
            uc.emu_start(addr, SENTINEL)
            if self.left_body is not None:
                status, fault = "badret", self.left_body
            elif self.over_budget:
                status = "budget"
            elif uc.reg_read(U.UC_X86_REG_EIP) != SENTINEL:
                status = "fault"
        except UcError:
            status = "divide" if self._at_div(uc) else "fault"
            fault = uc.reg_read(U.UC_X86_REG_EIP)
        regs_out = [uc.reg_read(r) for r in GPR_UC]
        return Outcome(status, regs_out, bytes(uc.mem_read(0, MEM_SIZE)), fault)

    @staticmethod
    def _at_div(uc) -> bool:
        try:
            b = uc.mem_read(uc.reg_read(U.UC_X86_REG_EIP), 2)
        except UcError:
            return False                 # jumped somewhere unmapped
        return b[0] == 0xF7 and (b[1] >> 3) & 7 in (6, 7)   # div/idiv r/m32


class Fuzzer:
    def __init__(self, rng: random.Random, mod: LEModule):
        self.rng = rng
        self.data = next(o for o in mod.objects if not o.is_code)

    def word(self) -> int:
        r = self.rng.random()
        if r < 0.30:
            return self.rng.randrange(0, 16)
        if r < 0.50:
            return self.rng.choice(BOUNDARY)
        if r < 0.65:
            return self.rng.randrange(0, 0x10000)
        if r < 0.80:   # pointer into scratch
            return self.rng.randrange(SCRATCH[0], SCRATCH[1] - 0x1000) & ~3
        if r < 0.90:   # pointer into the data object
            return self.data.base + (self.rng.randrange(0, self.data.vsize - 64) & ~3)
        return self.rng.getrandbits(32)

    def regs(self) -> list[int]:
        regs = [self.word() for _ in range(8)]
        regs[4] = STACK_TOP - 4          # esp -> sentinel return address
        return regs

    def memory(self, base: bytearray, hot: set[int]) -> bytearray:
        mem = bytearray(base)
        mem[SCRATCH[0]:SCRATCH[1]] = self.rng.randbytes(SCRATCH[1] - SCRATCH[0])
        for a in hot:
            if self.rng.random() < 0.5:
                mem[a:a + 4] = self.word().to_bytes(4, "little")
        mem[STACK_TOP - 4:STACK_TOP] = SENTINEL.to_bytes(4, "little")
        return mem


def describe_diff(a: Outcome, b: Outcome) -> str:
    out = []
    for n, x, y in zip(NAMES, a.regs, b.regs):
        if x != y:
            out.append(f"{n}: x86={x:#010x} lifted={y:#010x}")
    if a.mem != b.mem:
        diffs = [i for i in range(len(a.mem)) if a.mem[i] != b.mem[i]]
        out.append(f"memory: {len(diffs)} bytes differ, first at {diffs[0]:#x} "
                   f"(x86={a.mem[diffs[0]]:#04x} lifted={b.mem[diffs[0]]:#04x})")
    return "; ".join(out)


def test_function(addr: int, cases: int, seed: int, mod: LEModule, base: bytearray,
                  ref: Reference, lifted: Lifted, body: set[int]) -> dict:
    rng = random.Random(seed ^ addr)
    fz = Fuzzer(rng, mod)
    lo, hi = fz.data.base, fz.data.base + fz.data.vsize
    hot: set[int] = set()
    ref.executed.clear()
    stats = {"agree_ok": 0, "agree_stop": 0, "mismatch": 0, "examples": []}
    for n in range(cases):
        regs = fz.regs()
        mem = fz.memory(base, hot)
        want = ref.run(addr, regs, mem)
        hot |= {a & ~3 for a in ref.reads if lo <= a < hi}
        got = lifted.run(addr, regs, mem)
        if want.status != got.status:
            stats["mismatch"] += 1
            if len(stats["examples"]) < 3:
                stats["examples"].append(f"case {n}: status x86={want.status} lifted={got.status} "
                                         f"(fault x86@{want.fault:#x} lifted@{got.fault:#x}) regs={[hex(r) for r in regs]}")
        elif want.status != "ok":
            stats["agree_stop"] += 1
        elif want.regs != got.regs or want.mem != got.mem:
            stats["mismatch"] += 1
            if len(stats["examples"]) < 3:
                stats["examples"].append(f"case {n}: {describe_diff(want, got)} regs={[hex(r) for r in regs]}")
        else:
            stats["agree_ok"] += 1
    stats["hot_globals"] = len(hot)
    stats["coverage"] = len(ref.executed & body) / max(1, len(body))
    return stats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=200)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--lib", default=str(ROOT / "build" / "liblifted.dylib"))
    ap.add_argument("addrs", nargs="*")
    args = ap.parse_args()

    mod = LEModule((ROOT / "work" / "exe" / "war.exe").read_bytes())
    base = base_memory(mod)
    code_obj = next(o for o in mod.objects if o.is_code)
    code = (code_obj.base, (code_obj.base + code_obj.vsize + 0xFFF) & ~0xFFF)
    lifted = Lifted(pathlib.Path(args.lib), code)
    ref = Reference(code, base)
    addrs = [int(a, 16) for a in args.addrs] or lifted.addrs
    d = disasm.build(mod)
    for a in lifted.addrs:
        ref.allowed |= set(lift.collect(d, a).insns)

    total_bad = 0
    for a in addrs:
        body = set(lift.collect(d, a).insns)
        s = test_function(a, args.cases, args.seed, mod, base, ref, lifted, body)
        total_bad += s["mismatch"]
        flag = "PASS" if s["mismatch"] == 0 and s["agree_ok"] > 0 else ("FAIL" if s["mismatch"] else "WEAK")
        print(f"{flag} f_{a:x}: ok={s['agree_ok']} both-stopped={s['agree_stop']} "
              f"mismatch={s['mismatch']} coverage={s['coverage']:.0%} hot-globals={s['hot_globals']}")
        for e in s["examples"]:
            print("     ", e)
    print(f"{len(addrs)} functions, {total_bad} mismatching cases")
    sys.exit(1 if total_bad else 0)


if __name__ == "__main__":
    main()
