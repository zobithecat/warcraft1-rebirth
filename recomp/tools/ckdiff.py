#!/usr/bin/env python3
"""Checkpoint diff: replay a function's entry state on Unicorn and on the
lifted whole-program code, and report where they part.

The state comes from build/war (RECOMP_TRACE build) run with
WAR_DUMP_AT=<hex function address>.  The function runs until it returns to
its caller; anything it does that needs the runtime (an INT, an HLE function)
stops both sides, which is reported, not compared.

Usage: ckdiff.py build/dump_<addr>.bin [--lib build/libgame.dylib]
"""
from __future__ import annotations

import argparse
import ctypes
import pathlib
import struct
import sys

from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INTR, UC_MODE_32, Uc, UcError
from unicorn import x86_const as U

ROOT = pathlib.Path(__file__).resolve().parents[1]
NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
GPR_UC = [U.UC_X86_REG_EAX, U.UC_X86_REG_ECX, U.UC_X86_REG_EDX, U.UC_X86_REG_EBX,
          U.UC_X86_REG_ESP, U.UC_X86_REG_EBP, U.UC_X86_REG_ESI, U.UC_X86_REG_EDI]
STOP = {0: "ok", 1: "fault", 2: "budget", 3: "divide", 4: "badret", 5: "trap", 6: "exit"}
LIMIT = 200_000_000


def load(path: pathlib.Path):
    raw = path.read_bytes()
    magic, addr, size, eflags = struct.unpack_from("<4I", raw, 0)
    regs = list(struct.unpack_from("<8I", raw, 16))
    sbase = list(struct.unpack_from("<6I", raw, 48))
    mem = raw[72:72 + size]
    if magic != 0x31504D44 or len(mem) != size:
        raise SystemExit(f"{path}: not a checkpoint dump")
    return addr, regs, eflags, sbase, mem


GDT_ADDR = 0x08000000      # outside the compared guest memory


def flat_segments(uc) -> None:
    """Load flat 4GB 32-bit code/data descriptors.  Without a GDT, Unicorn's
    stack segment is not marked 32-bit and push/pop use SP instead of ESP."""
    def desc(access: int) -> bytes:
        limit, base, flags = 0xFFFFF, 0, 0xC          # 4K granularity, 32-bit
        return struct.pack("<HHBBBB", limit & 0xFFFF, base & 0xFFFF, (base >> 16) & 0xFF, access,
                           (flags << 4) | (limit >> 16), base >> 24)
    uc.mem_map(GDT_ADDR, 0x1000)
    uc.mem_write(GDT_ADDR, bytes(8) + desc(0x9A) + desc(0x92))
    uc.reg_write(U.UC_X86_REG_GDTR, (0, GDT_ADDR, 0x17, 0))
    uc.reg_write(U.UC_X86_REG_CS, 0x08)
    for r in (U.UC_X86_REG_SS, U.UC_X86_REG_DS, U.UC_X86_REG_ES, U.UC_X86_REG_FS, U.UC_X86_REG_GS):
        uc.reg_write(r, 0x10)


def run_unicorn(addr, regs, eflags, mem):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0, len(mem))
    uc.mem_write(0, mem)
    flat_segments(uc)
    for r, v in zip(GPR_UC, regs):
        uc.reg_write(r, v)
    uc.reg_write(U.UC_X86_REG_EFLAGS, eflags)
    ret = struct.unpack_from("<I", mem, regs[4])[0]
    esp_after = regs[4] + 4
    state = {"status": "ok", "at": 0}

    def on_code(uc, a, size, _):
        if a == ret and uc.reg_read(U.UC_X86_REG_ESP) >= esp_after:
            uc.emu_stop()

    def on_intr(uc, intno, _):
        state["status"] = f"int (cpu exception/int {intno})"
        state["at"] = uc.reg_read(U.UC_X86_REG_EIP)
        uc.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_INTR, on_intr)
    try:
        uc.emu_start(addr, 0xFFFFFFFF, count=LIMIT)
    except UcError as e:
        state["status"] = f"fault ({e})"
        state["at"] = uc.reg_read(U.UC_X86_REG_EIP)
    if state["status"] == "ok" and uc.reg_read(U.UC_X86_REG_EIP) != ret:
        state["status"] = "limit"
        state["at"] = uc.reg_read(U.UC_X86_REG_EIP)
    return state, [uc.reg_read(r) for r in GPR_UC], bytes(uc.mem_read(0, len(mem)))


def run_lifted(lib, addr, regs, mem):
    r = (ctypes.c_uint32 * 8)(*regs)
    buf = ctypes.create_string_buffer(mem, len(mem))
    fault = ctypes.c_uint32()
    why = lib.lifted_run(addr, r, buf, len(mem), 0, 0, LIMIT, ctypes.byref(fault))
    return STOP.get(why, str(why)), fault.value, list(r), buf.raw[:len(mem)]


def diff_ranges(a: bytes, b: bytes, limit: int = 8) -> list[str]:
    out, page = [], 4096
    for p in range(0, len(a), page):
        if a[p:p + page] == b[p:p + page]:
            continue
        for i in range(p, p + page):
            if a[i] != b[i]:
                out.append(f"{i:#x}: unicorn={a[i]:#04x} lifted={b[i]:#04x}")
                if len(out) >= limit:
                    return out
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--lib", default=str(ROOT / "build" / "libgame.dylib"))
    args = ap.parse_args()
    addr, regs, eflags, sbase, mem = load(pathlib.Path(args.dump))
    print(f"function {addr:#x}  regs {' '.join(f'{n}={v:08x}' for n, v in zip(NAMES, regs))}")
    if any(sbase):
        print(f"  note: non-flat segment bases at entry {[hex(b) for b in sbase]} (Unicorn assumes flat)")
    lib = ctypes.CDLL(args.lib)
    lib.lifted_run.restype = ctypes.c_int
    lib.lifted_run.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p, ctypes.c_uint32,
                               ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int64, ctypes.POINTER(ctypes.c_uint32)]
    ust, uregs, umem = run_unicorn(addr, regs, eflags, mem)
    lst, lfault, lregs, lmem = run_lifted(lib, addr, regs, mem)
    print(f"unicorn: {ust['status']}" + (f" at {ust['at']:#x}" if ust["at"] else ""))
    print(f"lifted : {lst}" + (f" ({lfault:#x})" if lst != "ok" else ""))
    rd = [f"{n}: unicorn={x:#x} lifted={y:#x}" for n, x, y in zip(NAMES, uregs, lregs) if x != y]
    # Below the stack pointer at return is dead space; callees may have saved
    # segment selectors there, which are numbered differently on each side.
    dead = (min(regs[4], uregs[4], lregs[4]) - 0x10000, max(uregs[4], lregs[4]))
    md = [m for m in diff_ranges(umem, lmem, 64) if not dead[0] <= int(m.split(":")[0], 16) < dead[1]][:8]
    if not rd and not md and ust["status"] == "ok" and lst == "ok":
        print("IDENTICAL: the lifted code matches the original here")
        return
    for line in rd:
        print("  reg", line)
    for line in md:
        print("  mem", line)
    sys.exit(1)


if __name__ == "__main__":
    main()
