#!/usr/bin/env python3
"""Map war.exe's platform hooks: interrupt vector installs and the sound stack.

For every software interrupt reached directly (`int N`) or through Watcom's
int386()/int386x() (register values passed in a REGS struct), recover the
vector, AX and handler with a small per-function constant propagator.  Then
report which handlers get installed, and the call boundary between game code,
Blizzard's sound wrapper and the Miles AIL 3 library.

Usage: platform_map.py [war.exe]   -> recomp/work/platform_map.json + summary
"""
from __future__ import annotations

import bisect
import json
import pathlib
import sys
from collections import defaultdict
from dataclasses import dataclass

import capstone
from capstone import x86

import disasm
from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_EXE = ROOT / "work" / "exe" / "war.exe"

# Watcom int386(int, union REGS *in, union REGS *out) and
# int386x(int, union REGS *in, union REGS *out, struct SREGS *s).
# Identified from their bodies (see SCOPING.md): vector in eax, in-regs in edx.
INT386 = {0x33810: "int386", 0x33C45: "int386x"}
# Watcom inp()/outp() (bodies: `in al, dx` / `out dx, al` with dx = eax).
PORT_WRAPPERS = {0x337F6: "inp", 0x33802: "outp"}
# union REGS (DWORDREGS view): eax ebx ecx edx esi edi cflag
REGS_FIELDS = {0x00: "eax", 0x04: "ebx", 0x08: "ecx", 0x0C: "edx", 0x10: "esi", 0x14: "edi"}

# Address ranges established by call-graph analysis (SCOPING.md, "사운드").
AIL_RANGES = [(0x2F4B8, 0x2FCA0), (0x33C5E, 0x39A00)]   # DPMI helpers + AIL 3 core
SOUND_WRAPPER = (0x26300, 0x26F80)                        # Blizzard's sound module

R32 = {x86.X86_REG_EAX: "eax", x86.X86_REG_EBX: "ebx", x86.X86_REG_ECX: "ecx", x86.X86_REG_EDX: "edx",
       x86.X86_REG_ESI: "esi", x86.X86_REG_EDI: "edi", x86.X86_REG_EBP: "ebp", x86.X86_REG_ESP: "esp"}
# sub-register -> (parent, shift, mask)
SUBREG = {
    x86.X86_REG_AX: ("eax", 0, 0xFFFF), x86.X86_REG_AL: ("eax", 0, 0xFF), x86.X86_REG_AH: ("eax", 8, 0xFF),
    x86.X86_REG_BX: ("ebx", 0, 0xFFFF), x86.X86_REG_BL: ("ebx", 0, 0xFF), x86.X86_REG_BH: ("ebx", 8, 0xFF),
    x86.X86_REG_CX: ("ecx", 0, 0xFFFF), x86.X86_REG_CL: ("ecx", 0, 0xFF), x86.X86_REG_CH: ("ecx", 8, 0xFF),
    x86.X86_REG_DX: ("edx", 0, 0xFFFF), x86.X86_REG_DL: ("edx", 0, 0xFF), x86.X86_REG_DH: ("edx", 8, 0xFF),
    x86.X86_REG_SI: ("esi", 0, 0xFFFF), x86.X86_REG_DI: ("edi", 0, 0xFFFF),
}
SEGREGS = {x86.X86_REG_CS: "cs", x86.X86_REG_DS: "ds", x86.X86_REG_ES: "es"}


@dataclass(frozen=True)
class StackAddr:
    """Symbolic address: value of `base` register at function entry + offset."""
    base: str
    off: int


@dataclass(frozen=True)
class Partial:
    """Register with only some bits known (e.g. after `mov cl, 0x23`)."""
    value: int
    mask: int

    def bits(self, sh: int, mask: int) -> int | None:
        return (self.value >> sh) & mask if (self.mask >> sh) & mask == mask else None


class Propagator:
    """Straight-line constant propagation inside one function.

    Values are ints, StackAddr, or None (unknown).  Control flow is ignored
    except that facts are reset at labels (join points), which keeps the
    result sound for the straight-line setup code we care about.
    """

    def __init__(self, labels: set[int]):
        self.labels = labels
        self.reset()

    def reset(self) -> None:
        # The frame pointer survives join points: after the prologue
        # (`mov ebp, esp`) Watcom code never reassigns it within a function.
        frame = getattr(self, "reg", {}).get("ebp")
        self.reg = {r: None for r in R32.values()}
        self.reg["esp"] = StackAddr("esp0", 0)
        if isinstance(frame, StackAddr):
            self.reg["ebp"] = frame
        self.mem: dict[StackAddr, tuple[int, object]] = {}   # addr -> (size, value)
        self.seg = {"cs": "cs"}

    def addr_of(self, op) -> StackAddr | None:
        m = op.mem
        if m.index != 0 or m.base not in R32:
            return None
        b = self.reg[R32[m.base]]
        return StackAddr(b.base, b.off + m.disp) if isinstance(b, StackAddr) else None

    def read(self, op, ins):
        if op.type == x86.X86_OP_IMM:
            return op.imm & 0xFFFFFFFF
        if op.type == x86.X86_OP_REG:
            if op.reg in R32:
                v = self.reg[R32[op.reg]]
                return v.bits(0, 0xFFFFFFFF) if isinstance(v, Partial) else v
            if op.reg in SUBREG:
                p, sh, mask = SUBREG[op.reg]
                return self.sub(p, sh, mask)
            if op.reg in SEGREGS:
                return self.seg.get(SEGREGS[op.reg])
            return None
        if op.type == x86.X86_OP_MEM:
            a = self.addr_of(op)
            if a is not None and a in self.mem:
                return self.mem[a][1]
        return None

    def write(self, op, v) -> None:
        if op.type == x86.X86_OP_REG:
            if op.reg in R32:
                self.reg[R32[op.reg]] = v
            elif op.reg in SUBREG:
                p, sh, mask = SUBREG[op.reg]
                old = self.reg[p]
                if isinstance(v, str) and mask == 0xFFFF:
                    self.reg[p] = v  # segment selector copied through a 16-bit reg
                    return
                if isinstance(old, int):
                    old = Partial(old, 0xFFFFFFFF)
                elif not isinstance(old, Partial):
                    old = Partial(0, 0)
                field = mask << sh
                if isinstance(v, int):
                    new = Partial((old.value & ~field) | ((v & mask) << sh), old.mask | field)
                else:
                    new = Partial(old.value & ~field, old.mask & ~field)
                self.reg[p] = new.value if new.mask == 0xFFFFFFFF else (new if new.mask else None)
            elif op.reg in SEGREGS:
                self.seg[SEGREGS[op.reg]] = v
        elif op.type == x86.X86_OP_MEM:
            a = self.addr_of(op)
            if a is None:
                return
            self.mem[a] = (op.size, v)

    def step(self, ins: disasm.Insn) -> None:
        if ins.addr in self.labels:
            self.reset()
        i, ops = ins.id, ins.ops
        if i == x86.X86_INS_MOV or i == x86.X86_INS_MOVZX:
            self.write(ops[0], self.read(ops[1], ins))
        elif i == x86.X86_INS_XOR and len(ops) == 2 and ops[0].type == ops[1].type == x86.X86_OP_REG \
                and ops[0].reg == ops[1].reg:
            self.write(ops[0], 0)
        elif i == x86.X86_INS_LEA:
            a = self.addr_of(ops[1])
            if a is None and ops[1].mem.base == 0 and ops[1].mem.index == 0:
                self.write(ops[0], ops[1].mem.disp & 0xFFFFFFFF)
            else:
                self.write(ops[0], a)
        elif i == x86.X86_INS_PUSH:
            self._adj_esp(-4)
            sp = self.reg["esp"]
            if isinstance(sp, StackAddr):
                self.mem[sp] = (4, self.read(ops[0], ins))
        elif i == x86.X86_INS_POP:
            sp = self.reg["esp"]
            v = self.mem.get(sp, (4, None))[1] if isinstance(sp, StackAddr) else None
            self.write(ops[0], v)
            self._adj_esp(4)
        elif i in (x86.X86_INS_SUB, x86.X86_INS_ADD) and ops[0].type == x86.X86_OP_REG \
                and ops[0].reg == x86.X86_REG_ESP and ops[1].type == x86.X86_OP_IMM:
            self._adj_esp(-ops[1].imm if i == x86.X86_INS_SUB else ops[1].imm)
        elif i == x86.X86_INS_CALL:
            for r in ("eax", "ecx", "edx"):     # treat as clobbered (callee may use any)
                self.reg[r] = None
        elif ops and ops[0].type in (x86.X86_OP_REG, x86.X86_OP_MEM) and ops[0].access & capstone.CS_AC_WRITE:
            self.write(ops[0], None)

    def sub(self, p: str, sh: int, mask: int) -> int | None:
        v = self.reg[p]
        if isinstance(v, int):
            return (v >> sh) & mask
        if isinstance(v, Partial):
            return v.bits(sh, mask)
        return None

    def _adj_esp(self, d: int) -> None:
        sp = self.reg["esp"]
        self.reg["esp"] = StackAddr(sp.base, sp.off + d) if isinstance(sp, StackAddr) else None

    def regs_struct(self, ptr) -> dict[str, object]:
        """Register values in a REGS struct at `ptr`, in the shape classify_install() takes.

        Fields are assembled byte by byte, since code fills them through
        dword, word (regs.w.ax) or byte (regs.h.ah) stores.
        """
        if not isinstance(ptr, StackAddr):
            return {}
        fields = {}
        for off, name in REGS_FIELDS.items():
            value = mask = 0
            for b in range(4):
                ent = self.mem.get(StackAddr(ptr.base, ptr.off + off + b))
                if ent is None:
                    continue
                size, v = ent
                if isinstance(v, str) and b == 0:
                    fields[name] = v      # a segment selector
                    break
                if not isinstance(v, int):
                    continue
                span = min(size or 1, 4 - b)
                field = ((1 << (8 * span)) - 1) << (8 * b)
                value = (value & ~field) | ((v << (8 * b)) & field)
                mask |= field
            else:
                fields[name] = Partial(value, mask)
        part = lambda r, sh, m: fields[r].bits(sh, m) if isinstance(fields.get(r), Partial) else None
        edx = fields.get("edx")
        return {"ax": part("eax", 0, 0xFFFF), "ah": part("eax", 8, 0xFF), "al": part("eax", 0, 0xFF),
                "bl": part("ebx", 0, 0xFF), "cl": part("ecx", 0, 0xFF),
                "edx": edx.bits(0, 0xFFFFFFFF) if isinstance(edx, Partial) else edx}


def fmt(v) -> str | None:
    if isinstance(v, int):
        return hex(v)
    if isinstance(v, str):
        return v
    return None


def classify_install(vec_insn: str, regs: dict) -> dict | None:
    """Decode a get/set-vector request from resolved registers."""
    ax, ah, al, cl = regs.get("ax"), regs.get("ah"), regs.get("al"), regs.get("cl")
    if vec_insn == "21" and ah in (0x25, 0x35):
        # Phar Lap 386|DOS-Extender functions 2502h-250Ch take the vector in CL;
        # Watcom's CRT only runs them when its extender-type byte says Phar Lap.
        # Telling them apart: a plain DOS 25h for 02h-07h would hook CPU
        # exceptions (DOS/4GW code uses DPMI 0203h for that), so those are
        # Phar Lap.  08h-0Ch are also IRQ0-4 (timer, keyboard, ...), so there
        # only a resolved CL counts as evidence.  Known miss: a Phar Lap 250Ch
        # with an unresolved CL is reported as DOS 25h vector 0Ch.
        if ah == 0x25 and al is not None and (0x02 <= al <= 0x07 or (al <= 0x0C and cl is not None)):
            return {"api": f"PharLap 25{al:02X}h", "vector": cl, "handler": fmt(regs.get("edx")),
                    "note": "Phar Lap path"}
        name = "DOS 25h set vector" if ah == 0x25 else "DOS 35h get vector"
        return {"api": name, "vector": al, "handler": fmt(regs.get("edx")) if ah == 0x25 else None}
    if vec_insn == "33" and ax == 0x0C:
        return {"api": "mouse 0Ch event handler", "vector": None, "handler": fmt(regs.get("edx"))}
    if vec_insn == "31" and ax in (0x200, 0x201, 0x204, 0x205):
        names = {0x200: "DPMI get RM vector", 0x201: "DPMI set RM vector",
                 0x204: "DPMI get PM vector", 0x205: "DPMI set PM vector"}
        return {"api": names[ax], "vector": regs.get("bl"),
                "handler": fmt(regs.get("edx")) if ax in (0x201, 0x205) else None}
    return None


REGS_LOADS = {x86.X86_REG_EAX: 0x0, x86.X86_REG_EBX: 0x4, x86.X86_REG_ECX: 0x8, x86.X86_REG_EDX: 0xC}
WRAPPER_SCAN = 40  # instructions from function entry


def find_regs_wrappers(d: disasm.Disasm) -> dict[int, tuple[str, int]]:
    """Functions like intdos(): load eax/ebx/ecx/edx from a REGS struct whose
    pointer arrived in an argument register, then execute `int N`.
    Returns {function: (argument register holding the REGS pointer, N)}."""
    out = {}
    for f in d.func_starts:
        alias = {r: r for r in ("eax", "ebx", "ecx", "edx", "esi", "edi")}
        loads: dict[str, set[int]] = defaultdict(set)   # entry reg -> REGS offsets loaded
        a, n = f, 0
        while (ins := d.insns.get(a)) is not None and n < WRAPPER_SCAN:
            ops = ins.ops
            if ins.id == x86.X86_INS_MOV and len(ops) == 2 and ops[0].type == x86.X86_OP_REG:
                dst = R32.get(ops[0].reg)
                if ops[1].type == x86.X86_OP_REG and dst:
                    alias[dst] = alias.get(R32.get(ops[1].reg))
                elif ops[1].type == x86.X86_OP_MEM and ops[0].reg in REGS_LOADS and ops[1].mem.index == 0:
                    base = alias.get(R32.get(ops[1].mem.base))
                    if base and ops[1].mem.disp == REGS_LOADS[ops[0].reg]:
                        loads[base].add(ops[1].mem.disp)
                    if dst:
                        alias[dst] = None
                elif dst:
                    alias[dst] = None
            elif ins.id == x86.X86_INS_INT:
                full = [r for r, offs in loads.items() if offs == set(REGS_LOADS.values())]
                if full:
                    out[f] = (full[0], ins.ops[0].imm & 0xFF)
                break
            if d._terminates(ins):
                break
            a, n = ins.end, n + 1
    return out


def scan(d: disasm.Disasm) -> tuple[list[dict], list[dict]]:
    """Walk every function with a Propagator; collect interrupt and port I/O sites."""
    insns = d.sorted_insns()
    funcs = sorted(d.func_starts)
    branch_labels = d.labels | d.func_starts
    int_sites, port_sites = [], []
    regs_wrappers = find_regs_wrappers(d)
    k = 0
    while k < len(insns):
        f = insns[k].addr
        n = bisect.bisect_right(funcs, f)
        end = funcs[n] if n < len(funcs) else d.hi
        prop = Propagator(branch_labels - {f})
        j = k
        while j < len(insns) and insns[j].addr < end:
            ins = insns[j]
            target = ins.ops[0].imm & 0xFFFFFFFF \
                if ins.id == x86.X86_INS_CALL and ins.ops[0].type == x86.X86_OP_IMM else None
            if ins.id == x86.X86_INS_INT:
                vec = ins.ops[0].imm & 0xFF
                regs = {"ax": prop.sub("eax", 0, 0xFFFF), "bl": prop.sub("ebx", 0, 0xFF),
                        "cl": prop.sub("ecx", 0, 0xFF), "ah": prop.sub("eax", 8, 0xFF),
                        "al": prop.sub("eax", 0, 0xFF), "edx": prop.reg["edx"], "ds": prop.seg.get("ds")}
                int_sites.append(make_site(ins.addr, f, "int", vec, regs))
            elif target in INT386 and f not in INT386:
                vec = prop.reg["eax"]
                int_sites.append(make_site(ins.addr, f, INT386[target], vec if isinstance(vec, int) else None,
                                           prop.regs_struct(prop.reg["edx"])))
            elif target in regs_wrappers and f not in regs_wrappers:
                arg, vec = regs_wrappers[target]
                int_sites.append(make_site(ins.addr, f, f"regs@{target:x}", vec,
                                           prop.regs_struct(prop.reg[arg])))
            elif target in PORT_WRAPPERS and f not in PORT_WRAPPERS:
                # inp(port) / outp(port, value): Watcom passes port in eax, value in edx.
                kind = PORT_WRAPPERS[target]
                port_sites.append({"addr": hex(ins.addr), "func": hex(f), "via": kind,
                                   "port": fmt(prop.sub("eax", 0, 0xFFFF)),
                                   "value": fmt(prop.sub("edx", 0, 0xFF)) if kind == "outp" else None})
            elif ins.id in (x86.X86_INS_IN, x86.X86_INS_OUT) and f not in PORT_WRAPPERS:
                imm = next((op.imm & 0xFFFF for op in ins.ops if op.type == x86.X86_OP_IMM), None)
                port = imm if imm is not None else prop.sub("edx", 0, 0xFFFF)
                port_sites.append({"addr": hex(ins.addr), "func": hex(f), "via": ins.mnemonic,
                                   "port": fmt(port), "value": None})
            prop.step(ins)
            j += 1
        k = j
    return int_sites, port_sites


def make_site(addr: int, func: int, via: str, vec, regs: dict) -> dict:
    vkey = f"{vec:02x}" if isinstance(vec, int) else None
    site = {"addr": hex(addr), "func": hex(func), "via": via,
            "vector": f"{vec:02x}h" if isinstance(vec, int) else None,
            "ax": fmt(regs.get("ax")), "ah": fmt(regs.get("ah"))}
    inst = classify_install(vkey, regs) if vkey else None
    if inst:
        if isinstance(inst.get("vector"), int):
            inst["vector"] = f"{inst['vector']:02x}h"
        site["install"] = inst
    return site


def call_boundary(d: disasm.Disasm, inside, outside_ok=lambda a: True) -> dict:
    """Functions inside a region that are called from outside it, with callers."""
    funcs = sorted(d.func_starts)

    def func_of(a: int) -> int:
        return funcs[bisect.bisect_right(funcs, a) - 1]

    api, deps = defaultdict(set), defaultdict(set)
    for i in d.insns.values():
        if i.id == x86.X86_INS_CALL and i.ops[0].type == x86.X86_OP_IMM:
            t = i.ops[0].imm & 0xFFFFFFFF
            if inside(t) and not inside(i.addr) and outside_ok(i.addr):
                api[t].add(func_of(i.addr))
            if inside(i.addr) and not inside(t):
                deps[t].add(func_of(i.addr))
    return {"entry_points": {hex(t): sorted(hex(c) for c in cs) for t, cs in sorted(api.items())},
            "calls_out_to": {hex(t): sorted(hex(c) for c in cs) for t, cs in sorted(deps.items())}}


def main() -> None:
    exe = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_EXE
    mod = LEModule(exe.read_bytes())
    d = disasm.build(mod)

    sites, ports = scan(d)
    in_ail = lambda a: any(lo <= a < hi for lo, hi in AIL_RANGES)
    in_wrap = lambda a: SOUND_WRAPPER[0] <= a < SOUND_WRAPPER[1]
    funcs = sorted(d.func_starts)

    result = {
        "interrupt_sites": sites,
        "port_sites": ports,
        "vector_installs": [s for s in sites if "install" in s],
        "unresolved_int386": [s for s in sites if s["via"] != "int"
                              and (s["vector"] is None or (s["ax"] is None and s["ah"] is None))],
        "ail": {"ranges": [[hex(a), hex(b)] for a, b in AIL_RANGES],
                "functions": sum(1 for f in funcs if in_ail(f)),
                **call_boundary(d, in_ail)},
        "sound_wrapper": {"range": [hex(a) for a in SOUND_WRAPPER],
                          "functions": sum(1 for f in funcs if in_wrap(f)),
                          **call_boundary(d, in_wrap)},
        "ail_called_from_outside_wrapper": {
            t: cs for t, cs in call_boundary(d, in_ail, lambda a: not in_wrap(a))["entry_points"].items()},
    }
    out = ROOT / "work" / "platform_map.json"
    out.write_text(json.dumps(result, indent=2))

    print("== vector get/set sites")
    for s in result["vector_installs"]:
        i = s["install"]
        print(f"  {s['addr']} in {s['func']} via {s['via']:8} {i['api']:22} vec={i.get('vector')} "
              f"handler={i.get('handler')} {i.get('note', '')}")
    by_port = defaultdict(list)
    for p in ports:
        by_port[p["port"]].append(f"{p['via']}@{p['addr']}")
    print("== port I/O sites by port")
    for port, where in sorted(by_port.items(), key=lambda x: (x[0] is None, x[0] or "")):
        print(f"  {port}: {len(where)} {where[:6]}")
    print(f"== int386/int386x sites: {sum(1 for s in sites if s['via'] != 'int')}, "
          f"unresolved: {len(result['unresolved_int386'])}")
    for s in result["unresolved_int386"]:
        print(f"  {s['addr']} in {s['func']} vector={s['vector']} ax={s['ax']}")
    print(f"== AIL: {result['ail']['functions']} functions, "
          f"{len(result['ail']['entry_points'])} entry points called from outside")
    print(f"   called from outside the sound wrapper: {result['ail_called_from_outside_wrapper']}")
    print(f"== sound wrapper: {result['sound_wrapper']['functions']} functions, entry points:")
    for t, cs in result["sound_wrapper"]["entry_points"].items():
        print(f"  {t} <- {cs}")


if __name__ == "__main__":
    main()
