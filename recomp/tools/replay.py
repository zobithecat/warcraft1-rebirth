#!/usr/bin/env python3
"""Replay DOSBox-X captures: DOSBox (recorded) vs Unicorn vs lifted arm64.

Each capture (tools/capture.py) holds registers + 16MB memory at a function's
entry and at its return.  The same entry state is run on Unicorn and on the
lifted code built for the captured load addresses; all three exit states are
compared.  Memory that changed in DOSBox but was written by neither replay is
reported separately: between the two dumps the real machine kept running
interrupt handlers (timer tick at 0040:006C, keyboard, ...).

Usage: replay.py [--lib build/liblifted_rt.dylib]
"""
from __future__ import annotations

import argparse
import ctypes
import json
import pathlib
import sys

from unicorn import UC_ARCH_X86, UC_MODE_32, UC_PROT_EXEC, UC_PROT_READ, Uc, UcError
from unicorn import x86_const as U

from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]
CAP = ROOT / "work" / "capture"
MEM = 0x1000000
NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
GPR_UC = [U.UC_X86_REG_EAX, U.UC_X86_REG_ECX, U.UC_X86_REG_EDX, U.UC_X86_REG_EBX,
          U.UC_X86_REG_ESP, U.UC_X86_REG_EBP, U.UC_X86_REG_ESI, U.UC_X86_REG_EDI]
STOP = {0: "ok", 1: "fault", 2: "budget", 3: "divide", 4: "badret"}
BUDGET = 50_000_000


def code_range(bases: dict) -> tuple[int, int]:
    mod = LEModule((ROOT / "work" / "exe" / "war.exe").read_bytes(), {int(k): v for k, v in bases.items()})
    code = next(o for o in mod.objects if o.is_code)
    return code.base, (code.base + code.vsize + 0xFFF) & ~0xFFF


def run_unicorn(rec: dict, mem: bytes, code: tuple[int, int]) -> tuple[str, list[int], bytes]:
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0, MEM)
    uc.mem_write(0, mem)
    uc.mem_protect(code[0], code[1] - code[0], UC_PROT_READ | UC_PROT_EXEC)
    for reg, v in zip(GPR_UC, rec["regs_in"]):
        uc.reg_write(reg, v)
    uc.reg_write(U.UC_X86_REG_EFLAGS, 0x202)
    status = "ok"
    try:
        uc.emu_start(rec["func_rt"], rec["ret"], count=BUDGET)
        if uc.reg_read(U.UC_X86_REG_EIP) != rec["ret"]:
            status = "budget"
    except UcError as e:
        status = f"fault ({e})"
    return status, [uc.reg_read(r) for r in GPR_UC], bytes(uc.mem_read(0, MEM))


def run_lifted(lib, rec: dict, mem: bytes, code: tuple[int, int]) -> tuple[str, list[int], bytes]:
    regs = (ctypes.c_uint32 * 8)(*rec["regs_in"])
    buf = ctypes.create_string_buffer(mem, MEM)
    fault = ctypes.c_uint32()
    why = lib.lifted_run(rec["func_rt"], regs, buf, MEM, code[0], code[1], BUDGET, ctypes.byref(fault))
    if why < 0:
        return "not lifted", list(rec["regs_in"]), mem
    return STOP[why], list(regs), buf.raw[:MEM]


def changed(a: bytes, b: bytes) -> set[int]:
    if a == b:
        return set()
    # compare in 4KB pages first, then bytes, to keep this fast
    out = set()
    for p in range(0, MEM, 4096):
        if a[p:p + 4096] != b[p:p + 4096]:
            out.update(i for i in range(p, p + 4096) if a[i] != b[i])
    return out


def ranges(addrs: set[int]) -> str:
    if not addrs:
        return "-"
    s = sorted(addrs)
    out, start, prev = [], s[0], s[0]
    for a in s[1:]:
        if a != prev + 1:
            out.append((start, prev))
            start = a
        prev = a
    out.append((start, prev))
    txt = ", ".join(f"{a:#x}" + (f"-{b:#x}" if b != a else "") for a, b in out[:4])
    return txt + (f" (+{len(out) - 4} more)" if len(out) > 4 else "")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", default=str(ROOT / "build" / "liblifted_rt.dylib"))
    args = ap.parse_args()
    lib = ctypes.CDLL(args.lib)
    lib.lifted_run.restype = ctypes.c_int
    lib.lifted_run.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p, ctypes.c_uint32,
                               ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int64, ctypes.POINTER(ctypes.c_uint32)]
    bad = 0
    recs = sorted(CAP.glob("*_[0-9]*.json"))
    for path in recs:
        rec = json.loads(path.read_text())
        mem_in = (CAP / rec["in"]).read_bytes()
        mem_out = (CAP / rec["out"]).read_bytes()
        code = code_range(rec["bases"])
        u_status, u_regs, u_mem = run_unicorn(rec, mem_in, code)
        l_status, l_regs, l_mem = run_lifted(lib, rec, mem_in, code)

        d_dos = changed(mem_in, mem_out)
        d_uc = changed(mem_in, u_mem)
        d_lift = changed(mem_in, l_mem)
        written = d_uc | d_lift
        problems = []
        if u_status != "ok" or l_status != "ok":
            problems.append(f"status unicorn={u_status} lifted={l_status}")
        for who, regs in (("unicorn", u_regs), ("lifted", l_regs)):
            diff = [f"{n} dos={x:#x} {who}={y:#x}" for n, x, y in zip(NAMES, rec["regs_out"], regs) if x != y]
            if diff:
                problems.append(f"{who} regs: " + "; ".join(diff))
        if u_mem != l_mem:
            problems.append(f"unicorn vs lifted memory differs at {ranges(changed(u_mem, l_mem))}")
        # against DOSBox: every byte the function wrote must end up as DOSBox recorded it
        mism = {a for a in written if l_mem[a] != mem_out[a]}
        if mism:
            problems.append(f"lifted vs DOSBox memory differs at {ranges(mism)}")
        async_only = d_dos - written
        flag = "PASS" if not problems else "FAIL"
        bad += bool(problems)
        print(f"{flag} {path.stem}: f_{rec['func']:x} wrote {len(written)} bytes "
              f"(dosbox changed {len(d_dos)}; not by the function: {ranges(async_only)})")
        for p in problems:
            print("      ", p)
    print(f"{len(recs)} captures, {bad} failing")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
