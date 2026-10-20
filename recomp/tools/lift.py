#!/usr/bin/env python3
"""Lift functions of war.exe from 32-bit x86 to C.

Every function becomes `void f_<addr>(Cpu *c)` operating on registers kept in
C locals, flags in a local Flags struct, and guest memory through rd*/wr*
(recomp/runtime/x86.h).  Control flow inside a function becomes labels and
gotos; switch tables become C switches.  Registers and flags are written back
to the Cpu around calls, returns and runtime hooks, so they flow across
function boundaries like on the real CPU.

Two modes:
  * strict (default): a function is emitted only if every instruction in it is
    supported; otherwise it is skipped with a reason.  Used by the tests.
  * whole program (--all): every function is emitted; anything not translated
    becomes a runtime trap at that instruction, indirect and unknown calls go
    through the runtime's dispatcher, `int`/`in`/`out` go to runtime hooks.

Usage: lift.py OUT.c [ADDR ...]       (hex image addresses; default: the prototype set)
       lift.py OUT.c --all-leaf       (every game-region leaf function, strict)
       lift.py OUT.c --all            (whole program)
       ... --bases 1=0x1CB000,2=0x1FD000   (lift for the objects' run-time load addresses)
"""
from __future__ import annotations

import pathlib
import sys
from dataclasses import dataclass, field

from capstone import x86

import analyze
import disasm
from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_EXE = ROOT / "work" / "exe" / "war.exe"
PROTOTYPE = [0x139DC, 0x2B21C, 0x13270, 0x2A398, 0x102A4, 0x1007C]
MAX_BODY = 8000   # instructions; guards against runaway discovery


class Unsupported(Exception):
    pass


# capstone register -> (32-bit parent local, bit shift, width in bits)
REG = {}
for p, (r32, r16, r8l, r8h) in {
    "eax": (x86.X86_REG_EAX, x86.X86_REG_AX, x86.X86_REG_AL, x86.X86_REG_AH),
    "ecx": (x86.X86_REG_ECX, x86.X86_REG_CX, x86.X86_REG_CL, x86.X86_REG_CH),
    "edx": (x86.X86_REG_EDX, x86.X86_REG_DX, x86.X86_REG_DL, x86.X86_REG_DH),
    "ebx": (x86.X86_REG_EBX, x86.X86_REG_BX, x86.X86_REG_BL, x86.X86_REG_BH),
}.items():
    REG[r32], REG[r16], REG[r8l], REG[r8h] = (p, 0, 32), (p, 0, 16), (p, 0, 8), (p, 8, 8)
for p, (r32, r16) in {"esp": (x86.X86_REG_ESP, x86.X86_REG_SP), "ebp": (x86.X86_REG_EBP, x86.X86_REG_BP),
                      "esi": (x86.X86_REG_ESI, x86.X86_REG_SI), "edi": (x86.X86_REG_EDI, x86.X86_REG_DI)}.items():
    REG[r32], REG[r16] = (p, 0, 32), (p, 0, 16)
SEGS = {x86.X86_REG_ES: "SEG_ES", x86.X86_REG_CS: "SEG_CS", x86.X86_REG_SS: "SEG_SS",
        x86.X86_REG_DS: "SEG_DS", x86.X86_REG_FS: "SEG_FS", x86.X86_REG_GS: "SEG_GS"}
GPRS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
MASK = {8: "0xFFu", 16: "0xFFFFu", 32: "0xFFFFFFFFu"}
ACC = {1: x86.X86_REG_AL, 2: x86.X86_REG_AX, 4: x86.X86_REG_EAX}

COND = {
    x86.X86_INS_JO: "f.of", x86.X86_INS_JNO: "!f.of", x86.X86_INS_JB: "f.cf", x86.X86_INS_JAE: "!f.cf",
    x86.X86_INS_JE: "f.zf", x86.X86_INS_JNE: "!f.zf", x86.X86_INS_JBE: "f.cf || f.zf",
    x86.X86_INS_JA: "!f.cf && !f.zf", x86.X86_INS_JS: "f.sf", x86.X86_INS_JNS: "!f.sf",
    x86.X86_INS_JP: "f.pf", x86.X86_INS_JNP: "!f.pf", x86.X86_INS_JL: "f.sf != f.of",
    x86.X86_INS_JGE: "f.sf == f.of", x86.X86_INS_JLE: "f.zf || f.sf != f.of",
    x86.X86_INS_JG: "!f.zf && f.sf == f.of",
}
SETCC = {
    x86.X86_INS_SETO: "f.of", x86.X86_INS_SETNO: "!f.of", x86.X86_INS_SETB: "f.cf", x86.X86_INS_SETAE: "!f.cf",
    x86.X86_INS_SETE: "f.zf", x86.X86_INS_SETNE: "!f.zf", x86.X86_INS_SETBE: "(f.cf || f.zf)",
    x86.X86_INS_SETA: "(!f.cf && !f.zf)", x86.X86_INS_SETS: "f.sf", x86.X86_INS_SETNS: "!f.sf",
    x86.X86_INS_SETP: "f.pf", x86.X86_INS_SETNP: "!f.pf", x86.X86_INS_SETL: "(f.sf != f.of)",
    x86.X86_INS_SETGE: "(f.sf == f.of)", x86.X86_INS_SETLE: "(f.zf || f.sf != f.of)",
    x86.X86_INS_SETG: "(!f.zf && f.sf == f.of)",
}
BINARY = {x86.X86_INS_ADD: "add", x86.X86_INS_ADC: "add", x86.X86_INS_SUB: "sub", x86.X86_INS_SBB: "sub",
          x86.X86_INS_CMP: "sub", x86.X86_INS_AND: "&", x86.X86_INS_OR: "|", x86.X86_INS_XOR: "^",
          x86.X86_INS_TEST: "&"}
SHIFTS = {x86.X86_INS_SHL: "shl", x86.X86_INS_SAL: "shl", x86.X86_INS_SHR: "shr", x86.X86_INS_SAR: "sar",
          x86.X86_INS_ROL: "rol", x86.X86_INS_ROR: "ror"}
# string instruction -> (kind, element size)
STRING = {
    x86.X86_INS_MOVSB: ("movs", 1), x86.X86_INS_MOVSW: ("movs", 2), x86.X86_INS_MOVSD: ("movs", 4),
    x86.X86_INS_STOSB: ("stos", 1), x86.X86_INS_STOSW: ("stos", 2), x86.X86_INS_STOSD: ("stos", 4),
    x86.X86_INS_LODSB: ("lods", 1), x86.X86_INS_LODSW: ("lods", 2), x86.X86_INS_LODSD: ("lods", 4),
    x86.X86_INS_SCASB: ("scas", 1), x86.X86_INS_SCASW: ("scas", 2), x86.X86_INS_SCASD: ("scas", 4),
    x86.X86_INS_CMPSB: ("cmps", 1), x86.X86_INS_CMPSW: ("cmps", 2), x86.X86_INS_CMPSD: ("cmps", 4),
}
FAR_LOADS = {x86.X86_INS_LDS: "SEG_DS", x86.X86_INS_LES: "SEG_ES", x86.X86_INS_LFS: "SEG_FS",
             x86.X86_INS_LGS: "SEG_GS", x86.X86_INS_LSS: "SEG_SS"}
NO_OPS = {x86.X86_INS_NOP, x86.X86_INS_CLI, x86.X86_INS_STI, x86.X86_INS_WAIT}
# Functions whose body is replaced by the runtime (x86_hle) in whole-program
# mode.  0x3CC50 is the core of Watcom's int386()/int386x(): it pushes the
# address of an `int N; ret` stub (0x3CCF6 + 3*N) and "returns" into it, a
# computed jump through the stack that the lifted code cannot follow.
HLE = {0x3CC50: "int386 dispatch"}
# Functions the runtime may take over call by call: f_<addr> asks the runtime
# first (x86_wrap; nonzero means it handled the call, `ret` included) and
# otherwise runs the original code, lifted as f_<addr>_orig.  Used for the
# modern controls in runtime/game.c, which run where the game handles input.
WRAP = {0x1B468: "right click on the map", 0x1A2B0: "left button released"}


@dataclass
class Func:
    addr: int
    insns: dict[int, disasm.Insn] = field(default_factory=dict)
    targets: set[int] = field(default_factory=set)       # intra-function branch targets
    callees: set[int] = field(default_factory=set)        # direct calls and tail jumps
    switches: dict[int, list[int]] = field(default_factory=dict)   # jmp addr -> case targets
    holes: set[int] = field(default_factory=set)          # branch targets that are not decoded code


def collect(d: disasm.Disasm, f: int, whole: bool = False) -> Func:
    """Instructions reachable from f without following calls."""
    fn = Func(f)
    switch_at = {s.jump_addr: s.targets for s in d.switch_tables}
    work = [f]
    while work:
        a = work.pop()
        while a not in fn.insns and a not in fn.holes:
            ins = d.insns.get(a)
            if ins is None:
                if not whole:
                    raise Unsupported(f"undecoded code at {a:#x}")
                fn.holes.add(a)
                break
            fn.insns[a] = ins
            if len(fn.insns) > MAX_BODY:
                raise Unsupported("body too large")
            if ins.id == x86.X86_INS_CALL:
                if ins.ops[0].type == x86.X86_OP_IMM:
                    fn.callees.add(ins.ops[0].imm & 0xFFFFFFFF)
                elif not whole:
                    raise Unsupported(f"indirect call at {a:#x}")
            elif ins.id == x86.X86_INS_JMP or ins.id in disasm.COND_JUMPS:
                if ins.ops[0].type != x86.X86_OP_IMM:
                    if a in switch_at:
                        fn.switches[a] = switch_at[a]
                        fn.targets.update(switch_at[a])
                        work.extend(switch_at[a])
                    elif not whole:
                        raise Unsupported(f"indirect jump at {a:#x}")
                else:
                    t = ins.ops[0].imm & 0xFFFFFFFF
                    if t in d.func_starts and t != f:
                        if ins.id != x86.X86_INS_JMP and not whole:
                            raise Unsupported(f"conditional tail jump at {a:#x}")
                        fn.callees.add(t)        # tail call
                    else:
                        fn.targets.add(t)
                        work.append(t)
            if disasm.Disasm._terminates(ins):
                break
            a = ins.end
    return fn


PREFIX_BYTES = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}


def rep_prefix(i: disasm.Insn) -> int | None:
    """F2/F3 prefix read from the raw bytes.  Capstone drops it for some
    encodings: `f2 a5` (repne movsd) decodes as a bare movsd, presumably
    because F2 also selects the SSE movsd."""
    rep = None
    for b in i.bytes:
        if b not in PREFIX_BYTES:
            break
        if b in (0xF2, 0xF3):
            rep = b
    return rep


class Emitter:
    def __init__(self, fn: Func, d: disasm.Disasm, whole: bool = False, lifted: set[int] | None = None):
        self.fn, self.d, self.whole = fn, d, whole
        self.lifted = lifted if lifted is not None else set(fn.callees)

    def unsupported(self, i: disasm.Insn, why: str) -> list[str]:
        if not self.whole:
            raise Unsupported(f"{why} at {i.addr:#x}")
        text = f"{i.mnemonic} {i.op_str}".replace("\\", "").replace('"', "'")
        return [f'x86_trap(c, 0x{i.addr:X}u, "{text}");']

    # ---- operands -----------------------------------------------------------
    def reg_read(self, reg: int) -> tuple[str, int]:
        if reg in SEGS:
            return f"(uint32_t)c->sreg[{SEGS[reg]}]", 16
        if reg not in REG:
            raise Unsupported(f"register {reg}")
        p, sh, bits = REG[reg]
        if bits == 32:
            return p, 32
        return (f"(({p} >> {sh}) & {MASK[bits]})" if sh else f"({p} & {MASK[bits]})"), bits

    def reg_write(self, reg: int, val: str) -> str:
        if reg in SEGS:
            return f"x86_load_seg(c, {SEGS[reg]}, {val});"
        if reg not in REG:
            raise Unsupported(f"register {reg}")
        p, sh, bits = REG[reg]
        if bits == 32:
            return f"{p} = (uint32_t)({val});"
        m = int(MASK[bits][:-1], 16) << sh
        return f"{p} = ({p} & 0x{~m & 0xFFFFFFFF:X}u) | ((((uint32_t)({val})) & {MASK[bits]}) << {sh});"

    def addr(self, op, offset: int = 0) -> str:
        m = op.mem
        parts = []
        # Implicit DS/SS are flat in DOS/4GW; explicit overrides add the segment base.
        if m.segment not in (0, x86.X86_REG_DS, x86.X86_REG_SS):
            parts.append(f"c->sbase[{SEGS[m.segment]}]")
        if m.base:
            parts.append(self.reg_read(m.base)[0])
        if m.index:
            idx = self.reg_read(m.index)[0]
            parts.append(f"{idx}*{m.scale}u" if m.scale != 1 else idx)
        disp = (m.disp + offset) & 0xFFFFFFFF
        if disp or not parts:
            parts.append(f"0x{disp:X}u")
        return f"(uint32_t)({' + '.join(parts)})"

    def read(self, op, bits: int | None = None) -> str:
        if op.type == x86.X86_OP_REG:
            return self.reg_read(op.reg)[0]
        if op.type == x86.X86_OP_IMM:
            b = bits or op.size * 8
            return f"0x{op.imm & int(MASK[b][:-1], 16):X}u"
        if op.type == x86.X86_OP_MEM:
            return f"rd{op.size * 8}(c, {self.addr(op)})"
        raise Unsupported("operand type")

    def write(self, op, val: str) -> str:
        if op.type == x86.X86_OP_REG:
            return self.reg_write(op.reg, val)
        if op.type == x86.X86_OP_MEM:
            return f"wr{op.size * 8}(c, {self.addr(op)}, {val});"
        raise Unsupported("write to immediate")

    # ---- control flow ----------------------------------------------------------
    @staticmethod
    def spill() -> list[str]:
        return [f"c->r[{n.upper()}] = {n};" for n in GPRS] + ["c->f = f;"]

    @staticmethod
    def reload() -> list[str]:
        return [f"{n} = c->r[{n.upper()}];" for n in GPRS] + ["f = c->f;"]

    def leave(self) -> list[str]:
        return self.spill() + ["X86_LEAVE(c);", "return;"]

    def call_to(self, target: str | int, ret_addr: int | None, at: int) -> list[str]:
        """Call a function (constant address or C expression); ret_addr None = tail call."""
        s = []
        if ret_addr is not None:
            s += ["esp -= 4;", f"wr32(c, esp, 0x{ret_addr:X}u);"]
        s += self.spill()
        if isinstance(target, int) and target in self.lifted:
            s += [f"f_{target:x}(c);"]
        else:
            t = f"0x{target:X}u" if isinstance(target, int) else target
            s += [f"x86_call(c, {t}, 0x{at:X}u);"]
        if ret_addr is not None:     # tail calls return straight to our caller
            # A callee that returned past our frame (stack pointer above it)
            # unwound us too, e.g. the script interpreter's exit handlers at
            # 0x10498 pop their own return address: pass the return outward.
            s += [f"if (c->ret_to != 0x{ret_addr:X}u) {{",
                  f"    if (c->r[ESP] > esp + 4u) {{ X86_LEAVE(c); return; }}",
                  f"    x86_badret(c, 0x{at:X}u, 0x{ret_addr:X}u);",
                  "}"]
        s += self.reload()
        return s

    def goto(self, src: int, t: int) -> list[str]:
        if t in self.fn.holes:
            return [f'x86_trap(c, 0x{t:X}u, "jump into undecoded code");']
        s = [f"x86_tick(c, 0x{src:X}u);"] if t <= src else []
        return s + [f"goto L_{t:x};"]

    def branch(self, i: disasm.Insn, cond: str) -> list[str]:
        t = i.ops[0].imm & 0xFFFFFFFF
        if t in self.fn.targets or t in self.fn.holes:
            return [f"if ({cond}) {{", *self.goto(i.addr, t), "}"]
        # conditional tail jump into another function
        return [f"if ({cond}) {{", *self.call_to(t, None, i.addr), *self.leave(), "}"]

    # ---- instructions ------------------------------------------------------------
    def opsize(self, i: disasm.Insn) -> int:
        return 2 if i.prefix[2] == 0x66 else 4

    def lift(self, i: disasm.Insn) -> list[str]:
        ops, iid = i.ops, i.id
        if iid in STRING:
            return self.string_op(i)
        if rep_prefix(i) is not None and iid != x86.X86_INS_RET:
            return self.unsupported(i, f"rep prefix: {i.mnemonic}")
        if iid in NO_OPS:
            return []
        if iid == x86.X86_INS_MOV:
            return [self.write(ops[0], self.read(ops[1], ops[0].size * 8))]
        if iid == x86.X86_INS_MOVZX:
            return [self.write(ops[0], self.read(ops[1]))]
        if iid == x86.X86_INS_MOVSX:
            st = {8: "int8_t", 16: "int16_t"}[ops[1].size * 8]
            return [self.write(ops[0], f"(uint32_t)(int32_t)({st})({self.read(ops[1])})")]
        if iid == x86.X86_INS_LEA:
            return [self.write(ops[0], self.addr(ops[1]))]
        if iid in BINARY:
            bits = ops[0].size * 8
            a, b = self.read(ops[0]), self.read(ops[1], bits)
            kind = BINARY[iid]
            if kind in ("add", "sub"):
                carry = "f.cf" if iid in (x86.X86_INS_ADC, x86.X86_INS_SBB) else "0"
                expr = f"{kind}{bits}(&f, {a}, {b}, {carry})"
            else:
                expr = f"logic{bits}(&f, ({a}) {kind} ({b}))"
            if iid in (x86.X86_INS_CMP, x86.X86_INS_TEST):
                return [f"{expr};"]
            return [self.write(ops[0], expr)]
        if iid in (x86.X86_INS_INC, x86.X86_INS_DEC, x86.X86_INS_NEG):
            bits = ops[0].size * 8
            name = {x86.X86_INS_INC: "inc", x86.X86_INS_DEC: "dec", x86.X86_INS_NEG: "neg"}[iid]
            return [self.write(ops[0], f"{name}{bits}(&f, {self.read(ops[0])})")]
        if iid == x86.X86_INS_NOT:
            return [self.write(ops[0], f"~({self.read(ops[0])})")]
        if iid in SHIFTS:
            bits = ops[0].size * 8
            n = "1u" if len(ops) == 1 else self.read(ops[1], 8)
            return [self.write(ops[0], f"{SHIFTS[iid]}{bits}(&f, {self.read(ops[0])}, {n})")]
        if iid == x86.X86_INS_IMUL:
            bits = ops[0].size * 8
            if len(ops) == 1:
                return self.mul_wide(ops[0], signed=True)
            if bits not in (16, 32):
                return self.unsupported(i, "imul width")
            src = (self.read(ops[0]), self.read(ops[1], bits)) if len(ops) == 2 else \
                  (self.read(ops[1]), self.read(ops[2], bits))
            return [self.write(ops[0], f"imul{bits}(&f, {src[0]}, {src[1]})")]
        if iid == x86.X86_INS_MUL:
            return self.mul_wide(ops[0], signed=False)
        if iid in (x86.X86_INS_DIV, x86.X86_INS_IDIV):
            return self.divide(i, ops[0], signed=iid == x86.X86_INS_IDIV)
        if iid == x86.X86_INS_CWDE:
            return ["eax = (uint32_t)(int32_t)(int16_t)eax;"]
        if iid == x86.X86_INS_CDQ:
            return ["edx = ((int32_t)eax < 0) ? 0xFFFFFFFFu : 0u;"]
        if iid == x86.X86_INS_CBW:
            return [self.reg_write(x86.X86_REG_AX, "(uint32_t)(int16_t)(int8_t)eax")]
        if iid == x86.X86_INS_CWD:
            return [self.reg_write(x86.X86_REG_DX, "((int16_t)eax < 0) ? 0xFFFFu : 0u")]
        if iid == x86.X86_INS_XCHG:
            a, b = self.read(ops[0]), self.read(ops[1])
            return ["{", f"uint32_t t0 = {a}, t1 = {b};", self.write(ops[0], "t1"), self.write(ops[1], "t0"), "}"]
        if iid in SETCC:
            return [self.write(ops[0], f"({SETCC[iid]}) ? 1u : 0u")]
        if iid == x86.X86_INS_PUSH:
            n = 4 if ops[0].type == x86.X86_OP_REG and ops[0].reg in SEGS and i.prefix[2] != 0x66 \
                else (self.opsize(i) if ops[0].type == x86.X86_OP_IMM else ops[0].size)
            return ["{", f"uint32_t t0 = {self.read(ops[0], n * 8)};", f"esp -= {n};",
                    f"wr{n * 8}(c, esp, t0);", "}"]
        if iid == x86.X86_INS_POP:
            n = 4 if ops[0].type == x86.X86_OP_REG and ops[0].reg in SEGS and i.prefix[2] != 0x66 else ops[0].size
            if ops[0].type != x86.X86_OP_REG:
                # pop to memory: the address uses esp after the pop
                return ["{", f"uint32_t t0 = rd{n * 8}(c, esp);", f"esp += {n};", self.write(ops[0], "t0"), "}"]
            val = "t0" if not (ops[0].reg in SEGS) else "t0 & 0xFFFFu"
            return ["{", f"uint32_t t0 = rd{n * 8}(c, esp);", f"esp += {n};", self.write(ops[0], val), "}"]
        if iid in (x86.X86_INS_PUSHFD, x86.X86_INS_PUSHF):
            n = 4 if iid == x86.X86_INS_PUSHFD else 2
            return [f"esp -= {n};", f"wr{n * 8}(c, esp, x86_pack_flags(&f));"]
        if iid in (x86.X86_INS_POPFD, x86.X86_INS_POPF):
            n = 4 if iid == x86.X86_INS_POPFD else 2
            return [f"x86_unpack_flags(&f, rd{n * 8}(c, esp));", f"esp += {n};"]
        if iid == x86.X86_INS_PUSHAL:
            return ["{", "uint32_t sp0 = esp;",
                    *[f"esp -= 4; wr32(c, esp, {r});" for r in ("eax", "ecx", "edx", "ebx")],
                    "esp -= 4; wr32(c, esp, sp0);",
                    *[f"esp -= 4; wr32(c, esp, {r});" for r in ("ebp", "esi", "edi")], "}"]
        if iid == x86.X86_INS_POPAL:
            return [*[f"{r} = rd32(c, esp); esp += 4;" for r in ("edi", "esi", "ebp")], "esp += 4;",
                    *[f"{r} = rd32(c, esp); esp += 4;" for r in ("ebx", "edx", "ecx", "eax")]]
        if iid in FAR_LOADS:
            seg = FAR_LOADS[iid]
            return ["{", f"uint32_t t0 = rd32(c, {self.addr(ops[1])});",
                    f"uint32_t t1 = rd16(c, {self.addr(ops[1], 4)});",
                    f"x86_load_seg(c, {seg}, t1);", self.write(ops[0], "t0"), "}"]
        if iid == x86.X86_INS_LEAVE:
            return ["esp = ebp;", "ebp = rd32(c, esp);", "esp += 4;"]
        if iid == x86.X86_INS_CLC:
            return ["f.cf = 0;"]
        if iid == x86.X86_INS_STC:
            return ["f.cf = 1;"]
        if iid == x86.X86_INS_CMC:
            return ["f.cf = !f.cf;"]
        if iid == x86.X86_INS_CLD:
            return ["f.df = 0;"]
        if iid == x86.X86_INS_STD:
            return ["f.df = 1;"]
        if iid == x86.X86_INS_INT:
            return [*self.spill(), f"x86_int(c, 0x{ops[0].imm & 0xFF:X}, 0x{i.addr:X}u);", *self.reload()]
        if iid in (x86.X86_INS_RCL, x86.X86_INS_RCR):
            bits = ops[0].size * 8
            n = "1u" if len(ops) == 1 else self.read(ops[1], 8)
            name = "rcl" if iid == x86.X86_INS_RCL else "rcr"
            return [self.write(ops[0], f"{name}{bits}(&f, {self.read(ops[0])}, {n})")]
        if iid == x86.X86_INS_SAHF:
            return ["x86_unpack_flags(&f, (x86_pack_flags(&f) & ~0xFFu) | ((eax >> 8) & 0xD5u));"]
        if iid == x86.X86_INS_LAHF:
            return [self.reg_write(x86.X86_REG_AH, "x86_pack_flags(&f) & 0xD7u")]
        if iid in (x86.X86_INS_LAR, x86.X86_INS_LSL):
            # DOS/4GW selectors are flat 4GB present data/code descriptors.
            val = "0xFFFFFFFFu" if iid == x86.X86_INS_LSL else "0x00CFF300u"
            return [self.write(ops[0], val), "f.zf = 1;"]
        if iid in (x86.X86_INS_FNINIT, x86.X86_INS_FLDCW, x86.X86_INS_FNSTCW):
            # Behave like a 386 without a coprocessor: these do nothing, so the
            # CRT's probe (fninit; fnstcw) reads back 0 and never uses the FPU.
            return []
        if iid == x86.X86_INS_INT3:
            return self.unsupported(i, "int3")
        if iid in (x86.X86_INS_IN, x86.X86_INS_OUT):
            return self.port_io(i)
        if iid in COND:
            return self.branch(i, COND[iid])
        if iid in (x86.X86_INS_JECXZ, x86.X86_INS_JCXZ):
            return self.branch(i, "ecx == 0" if iid == x86.X86_INS_JECXZ else "(ecx & 0xFFFFu) == 0")
        if iid in (x86.X86_INS_LOOP, x86.X86_INS_LOOPE, x86.X86_INS_LOOPNE):
            extra = {x86.X86_INS_LOOP: "", x86.X86_INS_LOOPE: " && f.zf", x86.X86_INS_LOOPNE: " && !f.zf"}[iid]
            return ["ecx -= 1;", *self.branch(i, f"ecx != 0{extra}")]
        if iid == x86.X86_INS_JMP:
            if ops[0].type != x86.X86_OP_IMM:
                return self.indirect_jump(i)
            t = ops[0].imm & 0xFFFFFFFF
            if t in self.fn.targets or t in self.fn.holes:
                return self.goto(i.addr, t)
            return self.call_to(t, None, i.addr) + self.leave()        # tail call
        if iid == x86.X86_INS_CALL:
            if ops[0].type == x86.X86_OP_IMM:
                return self.call_to(ops[0].imm & 0xFFFFFFFF, i.end, i.addr)
            if not self.whole:
                raise Unsupported(f"indirect call at {i.addr:#x}")
            return ["{", f"uint32_t tgt = {self.read(ops[0], 32)};", *self.call_to("tgt", i.end, i.addr), "}"]
        if iid == x86.X86_INS_RET:
            n = ops[0].imm if ops else 0
            return ["c->ret_to = rd32(c, esp);", f"esp += {4 + n}u;"] + self.leave()
        if iid == x86.X86_INS_RETF:
            n = ops[0].imm if ops else 0
            return ["c->ret_to = rd32(c, esp);", f"esp += {8 + n}u;"] + self.leave()
        if iid == x86.X86_INS_IRETD:
            return ["c->ret_to = rd32(c, esp);", "x86_unpack_flags(&f, rd32(c, esp + 8));",
                    "esp += 12u;"] + self.leave()
        return self.unsupported(i, f"instruction {i.mnemonic} {i.op_str}")

    def indirect_jump(self, i: disasm.Insn) -> list[str]:
        tgt = self.read(i.ops[0], 32)
        if i.addr in self.fn.switches:
            cases = sorted(set(self.fn.switches[i.addr]))
            return ["{", f"uint32_t tgt = {tgt};", "switch (tgt) {",
                    *[f"case 0x{t:X}u: goto L_{t:x};" for t in cases],
                    f'default: x86_trap(c, 0x{i.addr:X}u, "switch target outside table");', "}", "}"]
        if not self.whole:
            raise Unsupported(f"indirect jump at {i.addr:#x}")
        return ["{", f"uint32_t tgt = {tgt};", *self.call_to("tgt", None, i.addr), *self.leave(), "}"]

    def port_io(self, i: disasm.Insn) -> list[str]:
        # The runtime may run guest interrupt handlers while serving a port
        # (input arrives while the game polls), so registers go to the Cpu first.
        ops = i.ops
        if i.id == x86.X86_INS_IN:
            n = ops[0].size
            port = self.read(ops[1], 16) if ops[1].type == x86.X86_OP_IMM else "(edx & 0xFFFFu)"
            return ["{", f"uint32_t port = {port};", *self.spill(),
                    f"uint32_t v = x86_in(c, port, {n}, 0x{i.addr:X}u);", *self.reload(),
                    self.write(ops[0], "v"), "}"]
        n = ops[1].size
        port = self.read(ops[0], 16) if ops[0].type == x86.X86_OP_IMM else "(edx & 0xFFFFu)"
        return ["{", f"uint32_t port = {port}, v = {self.read(ops[1])};", *self.spill(),
                f"x86_out(c, port, v, {n}, 0x{i.addr:X}u);", *self.reload(), "}"]

    def string_op(self, i: disasm.Insn) -> list[str]:
        kind, n = STRING[i.id]
        bits = n * 8
        rep_byte = rep_prefix(i)
        rep = rep_byte is not None
        # REPNE on movs/stos/lods behaves like REP (Watcom emits f2 a4 / f2 a5).
        until = None
        if rep and kind in ("scas", "cmps"):
            until = "!f.zf" if rep_byte == 0xF3 else "f.zf"   # repe stops on ZF=0
        seg = next((op.mem.segment for op in i.ops if op.type == x86.X86_OP_MEM
                    and op.mem.segment not in (0, x86.X86_REG_ES)), x86.X86_REG_DS)
        src = f"c->sbase[{SEGS.get(seg, 'SEG_DS')}] + esi"
        dst = "c->sbase[SEG_ES] + edi"
        step = f"(f.df ? -{n} : {n})"
        acc = self.reg_read(ACC[n])[0]
        body = {
            "movs": [f"wr{bits}(c, {dst}, rd{bits}(c, {src}));", f"esi += {step}; edi += {step};"],
            "stos": [f"wr{bits}(c, {dst}, {acc});", f"edi += {step};"],
            "lods": [self.reg_write(ACC[n], f"rd{bits}(c, {src})"), f"esi += {step};"],
            "scas": [f"sub{bits}(&f, {acc}, rd{bits}(c, {dst}), 0);", f"edi += {step};"],
            "cmps": [f"sub{bits}(&f, rd{bits}(c, {src}), rd{bits}(c, {dst}), 0);", f"esi += {step}; edi += {step};"],
        }[kind]
        if not rep:
            return body
        stop = [f"if ({until}) break;"] if until else []
        return ["while (ecx != 0) {", *body, "ecx -= 1;", *stop, "}"]

    def mul_wide(self, op, signed: bool) -> list[str]:
        bits = op.size * 8
        src = self.read(op)
        if bits == 32:
            if signed:
                return ["{", f"int64_t w = (int64_t)(int32_t)eax * (int32_t)({src});",
                        "eax = (uint32_t)w; edx = (uint32_t)((uint64_t)w >> 32);",
                        "f.cf = f.of = w != (int32_t)w;", "}"]
            return ["{", f"uint64_t w = (uint64_t)eax * (uint32_t)({src});",
                    "eax = (uint32_t)w; edx = (uint32_t)(w >> 32);", "f.cf = f.of = edx != 0;", "}"]
        if bits == 16:
            if signed:
                return ["{", f"int32_t w = (int32_t)(int16_t)eax * (int16_t)({src});",
                        self.reg_write(x86.X86_REG_AX, "(uint32_t)w"),
                        self.reg_write(x86.X86_REG_DX, "(uint32_t)w >> 16"),
                        "f.cf = f.of = w != (int16_t)w;", "}"]
            return ["{", f"uint32_t w = (eax & 0xFFFFu) * ({src});",
                    self.reg_write(x86.X86_REG_AX, "w"), self.reg_write(x86.X86_REG_DX, "w >> 16"),
                    "f.cf = f.of = (w >> 16) != 0;", "}"]
        if signed:
            return ["{", f"int32_t w = (int32_t)(int8_t)eax * (int8_t)({src});",
                    self.reg_write(x86.X86_REG_AX, "(uint32_t)w"), "f.cf = f.of = w != (int8_t)w;", "}"]
        return ["{", f"uint32_t w = (eax & 0xFFu) * ({src});",
                self.reg_write(x86.X86_REG_AX, "w"), "f.cf = f.of = (w >> 8) != 0;", "}"]

    def divide(self, i, op, signed: bool) -> list[str]:
        src = self.read(op)
        at = f"0x{i.addr:X}u"
        if op.size == 4:
            if signed:
                return ["{", f"int32_t dv = (int32_t)({src});",
                        "int64_t dd = (int64_t)(((uint64_t)edx << 32) | eax);",
                        f"if (dv == 0) x86_stop(c, STOP_DIVIDE, {at});",
                        "int64_t q = dd / dv, r = dd % dv;",
                        f"if (q != (int32_t)q) x86_stop(c, STOP_DIVIDE, {at});",
                        "eax = (uint32_t)q; edx = (uint32_t)r;", "}"]
            return ["{", f"uint32_t dv = {src};", "uint64_t dd = ((uint64_t)edx << 32) | eax;",
                    f"if (dv == 0) x86_stop(c, STOP_DIVIDE, {at});",
                    "uint64_t q = dd / dv;",
                    f"if (q >> 32) x86_stop(c, STOP_DIVIDE, {at});",
                    "eax = (uint32_t)q; edx = (uint32_t)(dd % dv);", "}"]
        if op.size == 2:
            if signed:
                return ["{", f"int32_t dv = (int16_t)({src});",
                        "int32_t dd = (int32_t)(((edx & 0xFFFFu) << 16) | (eax & 0xFFFFu));",
                        f"if (dv == 0) x86_stop(c, STOP_DIVIDE, {at});",
                        "int32_t q = dd / dv, r = dd % dv;",
                        f"if (q != (int16_t)q) x86_stop(c, STOP_DIVIDE, {at});",
                        self.reg_write(x86.X86_REG_AX, "(uint32_t)q"), self.reg_write(x86.X86_REG_DX, "(uint32_t)r"), "}"]
            return ["{", f"uint32_t dv = {src};", "uint32_t dd = ((edx & 0xFFFFu) << 16) | (eax & 0xFFFFu);",
                    f"if (dv == 0) x86_stop(c, STOP_DIVIDE, {at});",
                    "uint32_t q = dd / dv;", f"if (q >> 16) x86_stop(c, STOP_DIVIDE, {at});",
                    self.reg_write(x86.X86_REG_AX, "q"), self.reg_write(x86.X86_REG_DX, "dd % dv"), "}"]
        if signed:
            return ["{", f"int32_t dv = (int8_t)({src});", "int32_t dd = (int16_t)(eax & 0xFFFFu);",
                    f"if (dv == 0) x86_stop(c, STOP_DIVIDE, {at});",
                    "int32_t q = dd / dv, r = dd % dv;", f"if (q != (int8_t)q) x86_stop(c, STOP_DIVIDE, {at});",
                    self.reg_write(x86.X86_REG_AL, "(uint32_t)q"), self.reg_write(x86.X86_REG_AH, "(uint32_t)r"), "}"]
        return ["{", f"uint32_t dv = {src};", "uint32_t dd = eax & 0xFFFFu;",
                f"if (dv == 0) x86_stop(c, STOP_DIVIDE, {at});",
                "uint32_t q = dd / dv;", f"if (q >> 8) x86_stop(c, STOP_DIVIDE, {at});",
                self.reg_write(x86.X86_REG_AL, "q"), self.reg_write(x86.X86_REG_AH, "dd % dv"), "}"]

    def emit(self) -> str:
        fn = self.fn
        body = []
        order = sorted(fn.insns)
        for k, a in enumerate(order):
            i = fn.insns[a]
            lines = self.lift(i)
            label = f"L_{a:x}:" if a in fn.targets or a == fn.addr else ""
            body.append(f"{label} /* {a:08x}: {i.mnemonic} {i.op_str} */")
            body += ["    " + s for s in lines]
            if disasm.Disasm._terminates(i):
                continue
            if i.end in fn.holes or (i.end not in fn.insns and self.whole):
                body.append(f'    x86_trap(c, 0x{i.end:X}u, "fell through into undecoded code");')
                continue
            if i.end not in fn.insns:
                raise Unsupported(f"falls through past body at {i.end:#x}")
            # straight-line fall-through into the next decoded address is implicit,
            # but a gap (code reached only by jumps) needs an explicit goto.
            nxt = order[k + 1] if k + 1 < len(order) else None
            if nxt != i.end:
                body.append(f"    goto L_{i.end:x};")
                fn.targets.add(i.end)
        head = [f"void f_{fn.addr:x}(Cpu *c) {{",
                f"    X86_ENTER(c, 0x{fn.addr:X}u);",
                "    " + " ".join(f"uint32_t {n} = c->r[{n.upper()}];" for n in GPRS),
                "    Flags f = c->f;", "    (void)f;"]
        # Code shared with a lower-addressed function (e.g. a common epilogue)
        # sorts before the entry point, so jump over it.
        if order and order[0] != fn.addr:
            head.append(f"    goto L_{fn.addr:x};")
        return "\n".join(head + body + ["}", ""])


def emit_function(d: disasm.Disasm, f: int, whole: bool, lifted: set[int] | None) -> tuple[Func, str]:
    if whole and f in HLE:
        return Func(f), (f"void f_{f:x}(Cpu *c) {{  /* {HLE[f]}: implemented by the runtime */\n"
                         f"    X86_ENTER(c, 0x{f:X}u);\n    x86_hle(c, 0x{f:X}u);\n    X86_LEAVE(c);\n}}\n")
    fn = collect(d, f, whole)
    em = Emitter(fn, d, whole, lifted)
    em.emit()                       # first pass may add fall-through labels
    code = Emitter(fn, d, whole, lifted).emit()
    if whole and f in WRAP:
        code = code.replace(f"void f_{f:x}(Cpu *c) {{", f"static void f_{f:x}_orig(Cpu *c) {{", 1)
        code += (f"void f_{f:x}(Cpu *c) {{  /* {WRAP[f]}: the runtime may take it over */\n"
                 f"    if (!x86_wrap(c, 0x{f:X}u)) f_{f:x}_orig(c);\n}}\n")
    return fn, code


def lift_functions(d: disasm.Disasm, roots: list[int]) -> tuple[dict[int, str], dict[int, str]]:
    """Strict mode: lift roots and, transitively, their callees.  Returns (code, skipped-with-reason)."""
    done, skipped, callees = {}, {}, {}
    work = list(roots)
    while work:
        f = work.pop()
        if f in done or f in skipped:
            continue
        try:
            fn, code = emit_function(d, f, False, None)
        except Unsupported as e:
            skipped[f] = str(e)
            continue
        done[f] = code
        callees[f] = fn.callees
        work += [t for t in fn.callees if t not in done]
    # drop functions whose callees could not be lifted
    changed = True
    while changed:
        changed = False
        for f in list(done):
            bad = [t for t in callees[f] if t not in done]
            if bad:
                skipped[f] = f"callee {bad[0]:#x} not lifted"
                del done[f]
                changed = True
    return done, skipped


def lift_whole(d: disasm.Disasm) -> tuple[dict[int, str], dict[int, str]]:
    """Whole-program mode: every known function."""
    funcs = set(d.func_starts)
    done, skipped = {}, {}
    for f in sorted(funcs):
        try:
            _, done[f] = emit_function(d, f, True, funcs)
        except Unsupported as e:
            skipped[f] = str(e)
    if skipped:     # calls to skipped functions must go through the dispatcher
        lifted = set(done)
        for f in list(done):
            _, done[f] = emit_function(d, f, True, lifted)
    return done, skipped


def leaf_game_functions(d: disasm.Disasm, delta: int = 0) -> list[int]:
    """Leaf functions below the game/platform split (`delta`: code relocation)."""
    out = []
    for f in sorted(d.func_starts):
        if f >= analyze.REGION_SPLIT + delta:
            continue
        try:
            fn = collect(d, f)
        except Unsupported:
            continue
        if not fn.callees:
            out.append(f)
    return out


def write_c(path: pathlib.Path, funcs: dict[int, str]) -> None:
    protos = "\n".join(f"void f_{a:x}(Cpu *c);" for a in sorted(funcs))
    table = "\n".join(f"    {{0x{a:X}u, f_{a:x}}}," for a in sorted(funcs))
    path.write_text(
        "/* Generated by recomp/tools/lift.py from war.exe. Do not edit. */\n"
        '#include "x86.h"\n\n'
        "#pragma clang diagnostic ignored \"-Wunused-label\"\n"
        "#pragma clang diagnostic ignored \"-Wunused-variable\"\n"
        "#pragma clang diagnostic ignored \"-Wunused-but-set-variable\"\n\n"
        f"{protos}\n\n" + "\n".join(funcs[a] for a in sorted(funcs)) +
        "\ntypedef struct { uint32_t addr; void (*fn)(Cpu *); } LiftedEntry;\n"
        "/* sorted by address; terminated by {0, 0} */\n"
        f"const LiftedEntry lifted_table[] = {{\n{table}\n    {{0, 0}}\n}};\n"
        f"const unsigned lifted_table_len = {len(funcs)}u;\n"
    )


def parse_bases(spec: str) -> dict[int, int]:
    """"1=0x1CB000,2=0x1FD000" -> {1: 0x1CB000, 2: 0x1FD000}"""
    return {int(k): int(v, 0) for k, v in (kv.split("=") for kv in spec.split(","))}


def main() -> None:
    out = pathlib.Path(sys.argv[1])
    args = sys.argv[2:]
    bases = {}
    if "--bases" in args:
        i = args.index("--bases")
        bases = parse_bases(args[i + 1])
        del args[i:i + 2]
    raw = DEFAULT_EXE.read_bytes()
    mod = LEModule(raw, bases)
    code = next(o for o in mod.objects if o.is_code)
    # Addresses on the command line are image addresses; shift them to where
    # the code object was loaded.
    delta = code.base - next(o for o in LEModule(raw).objects if o.is_code).base
    d = disasm.build(mod)
    if args == ["--all"]:
        done, skipped = lift_whole(d)
    else:
        if args == ["--all-leaf"]:
            roots = leaf_game_functions(d, delta)
        else:
            roots = [int(a, 16) + delta for a in args] or [a + delta for a in PROTOTYPE]
        done, skipped = lift_functions(d, roots)
    write_c(out, done)
    print(f"lifted {len(done)} functions -> {out}")
    reasons = {}
    for f, why in skipped.items():
        reasons.setdefault(why.split(" at ")[0], []).append(f)
    for why, fs in sorted(reasons.items(), key=lambda x: -len(x[1])):
        print(f"  skipped {len(fs):4d}: {why}  e.g. {', '.join(hex(f) for f in fs[:4])}")
    if args == ["--all"]:
        traps = sum(code.count("x86_trap(") for code in done.values())
        print(f"  runtime traps emitted: {traps}")


if __name__ == "__main__":
    main()
