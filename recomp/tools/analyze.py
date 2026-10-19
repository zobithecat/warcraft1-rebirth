#!/usr/bin/env python3
"""Scope a static recompilation of war.exe.

Loads the LE image, disassembles it, then counts what a recompiler and its
runtime would have to handle: functions, indirect control flow, software
interrupts (with DOS/DPMI/BIOS function numbers), port I/O, segment and
privileged instructions, x87 usage and self-modifying code.

Usage: analyze.py [war.exe]   (default: recomp/work/exe/war.exe)
Writes recomp/work/war.lst and recomp/work/scope.json, prints a summary.
"""
from __future__ import annotations

import bisect
import json
import pathlib
import sys
from collections import Counter, defaultdict

import capstone
from capstone import x86

import disasm
from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_EXE = ROOT / "work" / "exe" / "war.exe"

PADDING_MAX = 16
MIN_STUB_RUN = 16
WRAPPER_MAX = 48        # bytes from function start to the forwarding call
PORT_WRAPPER_MAX = 16
# Measured split between flat game logic and the DOS/hardware layer: below it
# there are no INT instructions and platform-specific code is confined to the
# network/modem module (see SCOPING.md).
REGION_SPLIT = 0x2F000
SEG_REGS = {x86.X86_REG_CS, x86.X86_REG_DS, x86.X86_REG_ES,
            x86.X86_REG_FS, x86.X86_REG_GS, x86.X86_REG_SS}
PRIV_IDS = {
    x86.X86_INS_CLI: "cli", x86.X86_INS_STI: "sti",
    x86.X86_INS_IRETD: "iretd", x86.X86_INS_IRET: "iret",
    x86.X86_INS_RETF: "retf", x86.X86_INS_LJMP: "ljmp", x86.X86_INS_LCALL: "lcall",
    x86.X86_INS_LDS: "lds", x86.X86_INS_LES: "les", x86.X86_INS_LFS: "lfs",
    x86.X86_INS_LGS: "lgs", x86.X86_INS_LSS: "lss", x86.X86_INS_LSL: "lsl",
    x86.X86_INS_LAR: "lar", x86.X86_INS_VERR: "verr", x86.X86_INS_VERW: "verw",
    x86.X86_INS_PUSHF: "pushf", x86.X86_INS_PUSHFD: "pushfd",
    x86.X86_INS_POPF: "popf", x86.X86_INS_POPFD: "popfd",
    x86.X86_INS_HLT: "hlt", x86.X86_INS_RDTSC: "rdtsc",
}
IO_IDS = {x86.X86_INS_IN, x86.X86_INS_OUT, x86.X86_INS_INSB, x86.X86_INS_INSD,
          x86.X86_INS_INSW, x86.X86_INS_OUTSB, x86.X86_INS_OUTSD, x86.X86_INS_OUTSW}
STRING_IDS = {x86.X86_INS_MOVSB, x86.X86_INS_MOVSW, x86.X86_INS_MOVSD,
              x86.X86_INS_STOSB, x86.X86_INS_STOSW, x86.X86_INS_STOSD,
              x86.X86_INS_LODSB, x86.X86_INS_LODSW, x86.X86_INS_LODSD,
              x86.X86_INS_SCASB, x86.X86_INS_SCASW, x86.X86_INS_SCASD,
              x86.X86_INS_CMPSB, x86.X86_INS_CMPSW, x86.X86_INS_CMPSD}
# Registers that carry an INT function number, by vector.
FUNC_REG = {0x21: "ah", 0x31: "ax", 0x10: "ah", 0x16: "ah", 0x33: "ax",
            0x1A: "ah", 0x2F: "ax", 0x15: "ah", 0x13: "ah"}
REG_PARTS = {
    "ah": {"ah": lambda v: v, "ax": lambda v: v >> 8, "eax": lambda v: (v >> 8) & 0xFF},
    "ax": {"ax": lambda v: v, "eax": lambda v: v & 0xFFFF},
    "dx": {"dx": lambda v: v, "edx": lambda v: v & 0xFFFF, "dl": None},
    "eax": {"eax": lambda v: v, "ax": None, "al": None, "ah": None},
}
LOOKBACK = 12


def is_padding(ins: disasm.Insn) -> bool:
    """Watcom alignment filler: nop, mov r,r, lea r,[r+0]."""
    if ins.id == x86.X86_INS_NOP:
        return True
    if ins.id == x86.X86_INS_MOV and len(ins.ops) == 2 and all(o.type == x86.X86_OP_REG for o in ins.ops):
        return ins.ops[0].reg == ins.ops[1].reg
    if ins.id == x86.X86_INS_LEA:
        dst, src = ins.ops
        m = src.mem
        return m.disp == 0 and m.index == 0 and m.base == dst.reg
    return False


def scan_unreferenced(d: disasm.Disasm) -> list[int]:
    """Find plausible function entries in undecoded gaps (after padding)."""
    found = []
    for start, end in d.gaps():
        a = start
        for _ in range(PADDING_MAX):
            if a >= end:
                break
            ins = d.decode(a)
            if ins is None or not is_padding(ins):
                break
            a = ins.end
        if a >= end or d.code.data[a - d.lo] == 0:
            continue
        # Accept only if a straight-line decode reaches a ret/jmp cleanly.
        b, ok = a, False
        while b < end:
            ins = d.decode(b)
            if ins is None or ins.bytes[:2] == b"\x00\x00":
                break
            if d._terminates(ins):
                ok = True
                break
            b = ins.end
        if ok:
            found.append(a)
    return found


def reg_value_before(insns: list[disasm.Insn], k: int, want: str) -> int | None:
    """Constant loaded into `want` (ah/ax/dx) shortly before insns[k]."""
    parts = REG_PARTS[want]
    for j in range(k - 1, max(-1, k - 1 - LOOKBACK), -1):
        i = insns[j]
        if i.id in (x86.X86_INS_CALL, x86.X86_INS_RET) or i.id in disasm.COND_JUMPS or i.id == x86.X86_INS_JMP:
            return None
        if not i.ops or i.ops[0].type != x86.X86_OP_REG or not i.ops[0].access & capstone.CS_AC_WRITE:
            continue
        name = REG_NAME.get(i.ops[0].reg)
        if not overlaps(name, want) or (want, name) in DISJOINT:
            continue
        if i.id == x86.X86_INS_MOV and i.ops[1].type == x86.X86_OP_IMM and parts.get(name):
            return parts[name](i.ops[1].imm & 0xFFFFFFFF)
        return None  # clobbered by something we can't evaluate
    return None


REG_NAME = {
    x86.X86_REG_AH: "ah", x86.X86_REG_AL: "al", x86.X86_REG_AX: "ax", x86.X86_REG_EAX: "eax",
    x86.X86_REG_DH: "dh", x86.X86_REG_DL: "dl", x86.X86_REG_DX: "dx", x86.X86_REG_EDX: "edx",
}
FAMILY = {"ah": "a", "al": "a", "ax": "a", "eax": "a", "dh": "d", "dl": "d", "dx": "d", "edx": "d"}
DISJOINT = {("ah", "al")}  # writing al leaves ah intact


def overlaps(name: str | None, want: str) -> bool:
    return name is not None and FAMILY.get(name) == FAMILY[want]


def find_int_stub_table(d: disasm.Disasm) -> tuple[int, int] | None:
    """Longest run of 3-byte `int N; ret` stubs (Watcom int386x dispatch)."""
    data, best, run_start, n = d.code.data, None, None, 0
    off = 0
    while off < d.code.vsize - 2:
        b0, b1, b2 = data[off], data[off + 1], data[off + 2]
        stub = (b0 == 0xCD and b2 == 0xC3) or (b0 == 0xCC and b1 == 0x90 and b2 == 0xC3)
        if stub:
            if run_start is None:
                run_start, n = off, 0
            n += 1
            off += 3
            continue
        if run_start is not None and n >= MIN_STUB_RUN and (best is None or n > best[1]):
            best = (run_start, n)
        run_start = None
        off += 1
    if best is None:
        return None
    return d.lo + best[0], d.lo + best[0] + 3 * best[1]


def call_graph(insns: list[disasm.Insn]) -> dict[int, list[int]]:
    """callee -> [index of call instruction in `insns`]."""
    g = defaultdict(list)
    for k, i in enumerate(insns):
        if i.id == x86.X86_INS_CALL and i.ops[0].type == x86.X86_OP_IMM:
            g[i.ops[0].imm & 0xFFFFFFFF].append(k)
    return g


def wrapper_closure(roots: set[int], callers: dict[int, list[int]], insns, func_of, max_size: int) -> set[int]:
    """Grow `roots` with small functions that just forward to a member."""
    fam = set(roots)
    while True:
        new = set()
        for f in fam:
            for k in callers.get(f, ()):
                g = func_of(insns[k].addr)
                if g is not None and g not in fam and insns[k].addr - g < max_size:
                    new.add(g)
        if not new:
            return fam
        fam |= new


def resolve_call_args(fam: set[int], callers, insns, func_of) -> Counter:
    """Constant first argument (eax, Watcom register convention) at external call sites."""
    out = Counter()
    for f in fam:
        for k in callers.get(f, ()):
            if func_of(insns[k].addr) in fam:
                continue
            v = reg_value_before(insns, k, "eax")
            out[f"{v:#x}" if v is not None else "dynamic"] += 1
    return out


def analyze(exe: pathlib.Path) -> dict:
    mod = LEModule(exe.read_bytes())
    d = disasm.build(mod)
    reachable = set(d.insns)
    reach_funcs = set(d.func_starts)

    stub = find_int_stub_table(d)
    in_stub = (lambda a: stub[0] <= a < stub[1]) if stub else (lambda a: False)
    unref = [a for a in scan_unreferenced(d) if not in_stub(a)]
    d.run([(a, True) for a in unref])
    # Pass 3 may chain into more gaps; repeat until stable.
    while more := [a for a in scan_unreferenced(d) if a not in d.insns and not in_stub(a)]:
        unref += more
        d.run([(a, True) for a in more])
    unref_set = set(d.insns) - reachable

    insns = [i for i in d.sorted_insns() if not in_stub(i.addr)]
    func_list = sorted(f for f in d.func_starts if not in_stub(f))

    def func_of(a: int) -> int | None:
        k = bisect.bisect_right(func_list, a) - 1
        return func_list[k] if k >= 0 else None

    def region(a: int) -> str:
        return "game" if a < REGION_SPLIT else "platform"

    callers = call_graph(insns)
    switch_jumps = {s.jump_addr for s in d.switch_tables}
    stats = {k: Counter() for k in ("indirect", "int", "int_func", "io", "priv", "segload",
                                    "fpu", "string", "segoverride", "by_region")}
    int_sites, io_sites = defaultdict(list), defaultdict(list)
    fpu_funcs, io_funcs, int_funcs = set(), set(), set()
    int_dispatchers, port_wrappers = set(), set()

    for k, i in enumerate(insns):
        where = "reach" if i.addr in reachable else "unref"
        reg = region(i.addr)
        cats = []
        if i.id in (x86.X86_INS_CALL, x86.X86_INS_JMP) and i.ops and i.ops[0].type != x86.X86_OP_IMM:
            if i.addr in switch_jumps:
                stats["indirect"][f"{where}:jmp switch-table"] += 1
            else:
                op = i.ops[0]
                if op.type == x86.X86_OP_REG:
                    form = "reg"
                elif op.mem.base == 0 and op.mem.index == 0:
                    form = "[global]"
                else:
                    form = "[reg+disp]"
                stats["indirect"][f"{where}:{i.mnemonic} {form}"] += 1
                cats.append("indirect")
        if stub and i.id == x86.X86_INS_LEA and stub[0] <= i.ops[1].mem.disp & 0xFFFFFFFF < stub[1]:
            int_dispatchers.add(func_of(i.addr))
        if i.id == x86.X86_INS_INT:
            vec = i.ops[0].imm & 0xFF
            stats["int"][f"{where}:int {vec:02x}h"] += 1
            want = FUNC_REG.get(vec)
            fn = reg_value_before(insns, k, want) if want else None
            key = f"int {vec:02x}h/{want}={fn:#x}" if fn is not None else f"int {vec:02x}h/{want or '-'}=?"
            stats["int_func"][f"{where}:{key}"] += 1
            int_sites[f"{vec:02x}"].append(i.addr)
            int_funcs.add(func_of(i.addr))
            cats.append("int")
        if i.id in IO_IDS:
            port = None
            for op in i.ops:
                if op.type == x86.X86_OP_IMM:
                    port = op.imm & 0xFFFF
            if port is None:
                port = reg_value_before(insns, k, "dx")
            f = func_of(i.addr)
            if port is None and f is not None and i.addr - f < PORT_WRAPPER_MAX:
                port_wrappers.add(f)
            pkey = f"{port:#05x}" if port is not None else "dx=?"
            stats["io"][f"{where}:{i.mnemonic} {pkey}"] += 1
            io_sites[pkey].append(i.addr)
            io_funcs.add(f)
            cats.append("port_io")
        if i.id in PRIV_IDS:
            stats["priv"][f"{where}:{PRIV_IDS[i.id]}"] += 1
            cats.append("priv")
        if i.ops and i.ops[0].type == x86.X86_OP_REG and i.ops[0].reg in SEG_REGS and i.id in (x86.X86_INS_MOV, x86.X86_INS_POP):
            stats["segload"][f"{where}:{i.mnemonic} {i.op_str.split(',')[0]}"] += 1
            cats.append("segload")
        if i.id not in STRING_IDS:
            seg = next((op.mem.segment for op in i.ops if op.type == x86.X86_OP_MEM
                        and op.mem.segment not in (0, x86.X86_REG_DS, x86.X86_REG_SS)), None)
            if seg:
                stats["segoverride"][f"{where}:{SEG_NAME.get(seg, seg)}:"] += 1
                cats.append(f"{SEG_NAME.get(seg, seg)}:")
        if i.mnemonic.startswith("f"):
            stats["fpu"][where] += 1
            fpu_funcs.add(func_of(i.addr))
            cats.append("fpu")
        if i.id in STRING_IDS:
            stats["string"][f"{where}:{i.mnemonic}"] += 1
        stats["by_region"][f"{reg}:insns"] += 1
        for c in cats:
            stats["by_region"][f"{reg}:{c}"] += 1

    int_family = wrapper_closure(int_dispatchers - {None}, callers, insns, func_of, WRAPPER_MAX)
    port_family = wrapper_closure(port_wrappers, callers, insns, func_of, WRAPPER_MAX)

    smc = sorted({t for t, refs in d.code_refs.items() if any(k == "write" for _, k in refs)})
    code_data_reads = sorted({t for t, refs in d.code_refs.items()
                              if any(k == "read" for _, k in refs) and t not in smc
                              and not in_stub(t)
                              and not any(s.table_addr - 4 * disasm.MAX_SWITCH_BIAS <= t
                                          < s.table_addr + 4 * len(s.targets)
                                          for s in d.switch_tables)})
    code_strings = sorted({t for t, refs in d.code_refs.items() if any(k == "string" for _, k in refs)})
    data_code_ptrs = {mod.fixup_target(f) for f in mod.fixups
                      if f.tgt_obj == d.code.index and not mod.obj_at(f.src_addr).is_code}

    sizes = sorted((func_list[n + 1] if n + 1 < len(func_list) else d.hi) - s
                   for n, s in enumerate(func_list))
    by_region_funcs = Counter(region(f) + ("" if f in reach_funcs else ":unref") for f in func_list)

    gaps = d.gaps()
    result = {
        "file": {"name": exe.name, "size": len(mod.raw)},
        "objects": [{"index": o.index, "base": hex(o.base), "size": o.vsize, "flags": o.describe_flags()}
                    for o in mod.objects],
        "entry": hex(mod.entry),
        "fixups": len(mod.fixups),
        "instructions": {"reachable": len(reachable), "unreferenced": len(unref_set - {a for a in unref_set if in_stub(a)}),
                         "total": len(insns)},
        "coverage": {"pass1_insns": d.pass1_insns, "decoded_pct": round(100 * d.coverage(), 2),
                     "remaining_gap_bytes": sum(b - a for a, b in gaps), "remaining_gaps": len(gaps)},
        "functions": {"reachable": len(reach_funcs - {f for f in reach_funcs if in_stub(f)}),
                      "unreferenced_candidates": len(set(unref)), "total": len(func_list),
                      "by_region": dict(sorted(by_region_funcs.items())),
                      "size_median": sizes[len(sizes) // 2], "size_p90": sizes[int(len(sizes) * 0.9)],
                      "size_max": sizes[-1]},
        "region_split": hex(REGION_SPLIT),
        "indirect_targets": {"code_ptrs_in_data": len(data_code_ptrs),
                             "switch_tables": len(d.switch_tables),
                             "switch_cases": sum(len(s.targets) for s in d.switch_tables)},
        "int_stub_table": ({"start": hex(stub[0]), "end": hex(stub[1]), "vectors": (stub[1] - stub[0]) // 3,
                            "dispatchers": sorted(hex(f) for f in int_dispatchers - {None}),
                            "family": sorted(hex(f) for f in int_family),
                            "vector_at_callsites": dict(resolve_call_args(int_family, callers, insns, func_of))}
                           if stub else None),
        "port_wrappers": {"family": sorted(hex(f) for f in port_family),
                          "port_at_callsites": dict(resolve_call_args(port_family, callers, insns, func_of))},
        "smc_slots": [hex(a) for a in smc],
        "code_data_reads": [hex(a) for a in code_data_reads],
        "strings_in_code": len(code_strings),
        "decode_conflicts": sorted({hex(a) for a in d.overlaps}),
        "funcs_with": {"int": len(int_funcs - {None}), "port_io": len(io_funcs - {None}),
                       "fpu": len(fpu_funcs - {None})},
        "int_sites": {k: [hex(a) for a in v] for k, v in sorted(int_sites.items())},
        "io_sites": {k: [hex(a) for a in v] for k, v in sorted(io_sites.items())},
    }
    for k, c in stats.items():
        result[k] = dict(sorted(c.items()))
    write_listing(d, reachable, ROOT / "work" / "war.lst")
    return result


SEG_NAME = {x86.X86_REG_CS: "cs", x86.X86_REG_ES: "es", x86.X86_REG_FS: "fs", x86.X86_REG_GS: "gs"}


def write_listing(d: disasm.Disasm, reachable: set[int], path: pathlib.Path) -> None:
    with path.open("w") as f:
        for i in d.sorted_insns():
            if i.addr in d.func_starts:
                f.write(f"\nsub_{i.addr:x}:{'' if i.addr in reachable else '   ; unreferenced'}\n")
            elif i.addr in d.labels:
                f.write(f"loc_{i.addr:x}:\n")
            f.write(f"    {i}\n")


def main() -> None:
    exe = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_EXE
    res = analyze(exe)
    (ROOT / "work" / "scope.json").write_text(json.dumps(res, indent=2))
    skip = {"int_sites", "io_sites", "code_data_reads", "objects"}
    for k, v in res.items():
        if k in skip:
            continue
        print(f"{k}: {json.dumps(v)}")


if __name__ == "__main__":
    main()
