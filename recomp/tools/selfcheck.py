#!/usr/bin/env python3
"""Consistency checks for the LE loader and disassembler.

Each check prints PASS/FAIL with numbers; exit status is non-zero on failure.
Usage: selfcheck.py [war.exe] [other LE exe ...]
"""
from __future__ import annotations

import pathlib
import sys

from capstone import x86

import disasm
from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT = [ROOT / "work" / "exe" / "war.exe", ROOT / "work" / "exe" / "setup.exe"]
MIN_STRING_START_RATIO = 0.95
STRING_PAD = 4

failures = 0


def check(name: str, ok: bool, detail: str) -> None:
    global failures
    print(f"  {'PASS' if ok else 'FAIL'}  {name}: {detail}")
    failures += not ok


def strings_start_cleanly(mod: LEModule) -> tuple[int, int]:
    """Relocated data->data pointers that hit a printable string should hit its first byte.

    Watcom pads string literals to 4 bytes and the pad bytes are not zeroed,
    so "start" means: the previous string's NUL is within the 4 bytes before.
    """
    hits = clean = 0
    for f in mod.fixups:
        src, tgt_obj = mod.obj_at(f.src_addr), mod.obj(f.tgt_obj)
        if src is None or src.is_code or tgt_obj.is_code:
            continue
        t = mod.fixup_target(f)
        try:
            s = mod.read(t, 8)
            before = mod.read(max(tgt_obj.base, t - STRING_PAD), t - max(tgt_obj.base, t - STRING_PAD))
        except KeyError:
            continue
        if all(0x20 <= c < 0x7F for c in s[:4]):
            hits += 1
            clean += t == tgt_obj.base or 0 in before
    return hits, clean


def run(path: pathlib.Path) -> None:
    print(f"== {path.name}")
    mod = LEModule(path.read_bytes())
    code = next(o for o in mod.objects if o.is_code)
    check("entry in code object", code.base <= mod.entry < code.end, hex(mod.entry))

    d = disasm.build(mod)
    starts = set(d.insns)

    ordered = d.sorted_insns()
    overlapping = [(p.addr, n.addr) for p, n in zip(ordered, ordered[1:]) if n.addr < p.end]
    check("decoded instructions don't overlap", not overlapping,
          f"{len(overlapping)} {[f'{a:x}/{b:x}' for a, b in overlapping[:5]]}")

    bad_branch = []
    for i in d.insns.values():
        if (i.id in (x86.X86_INS_CALL, x86.X86_INS_JMP) or i.id in disasm.COND_JUMPS) \
                and i.ops and i.ops[0].type == x86.X86_OP_IMM:
            t = i.ops[0].imm & 0xFFFFFFFF
            if d.in_code(t) and t not in starts:
                bad_branch.append((i.addr, t))
    check("direct branch targets are insn starts", not bad_branch,
          f"{len(bad_branch)} bad {[f'{a:x}->{t:x}' for a, t in bad_branch[:5]]}")

    sw_bad = [t for s in d.switch_tables for t in s.targets if t not in starts]
    check("switch-table targets decoded", not sw_bad, f"{len(d.switch_tables)} tables, {len(sw_bad)} bad")

    data_ptrs = {mod.fixup_target(f) for f in mod.fixups
                 if f.tgt_obj == code.index and not mod.obj_at(f.src_addr).is_code}
    undecoded = [t for t in data_ptrs if t not in starts]
    check("code pointers in data decode", not undecoded,
          f"{len(data_ptrs)} ptrs, {len(undecoded)} not insn starts {[hex(t) for t in undecoded[:5]]}")

    covered = set()
    for i in d.insns.values():
        covered.update(range(i.addr, i.end))
    code_fix = [f for f in mod.fixups if d.in_code(f.src_addr)]
    # Coverage, not correctness: the rest sit in unreached (dead library)
    # code, pointer tables and string blobs kept in the code object.
    inside = sum(1 for f in code_fix if f.src_addr in covered or f.src_addr in d.table_bytes)
    ratio = inside / max(1, len(code_fix))
    print(f"  info  code fixups inside decoded insns/tables: {inside}/{len(code_fix)} = {ratio:.1%}")

    # A relocated 32-bit operand must sit wholly inside its instruction.
    straddle = [f.src_addr for f in code_fix if f.src_addr in covered
                and (f.src_addr + 3) not in covered]
    check("fixups don't straddle instructions", not straddle, f"{len(straddle)} {[hex(a) for a in straddle[:5]]}")

    hits, clean = strings_start_cleanly(mod)
    r = clean / max(1, hits)
    check("data->data string pointers hit string starts", hits == 0 or r >= MIN_STRING_START_RATIO,
          f"{clean}/{hits} = {r:.1%}")
    print(f"  info  insns={len(d.insns)} funcs={len(d.func_starts)} coverage={100 * d.coverage():.2f}%")


def main() -> None:
    paths = [pathlib.Path(p) for p in sys.argv[1:]] or DEFAULT
    for p in paths:
        run(p)
    print("ALL PASS" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
