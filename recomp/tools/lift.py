#!/usr/bin/env python3
"""Lift functions of war.exe from 32-bit x86 to C (prototype).

Every function becomes `void f_<addr>(Cpu *c)` operating on registers kept in
C locals, flags in a local Flags struct, and guest memory through rd*/wr*
(recomp/runtime/x86.h).  Control flow inside a function becomes labels and
gotos.  A function is only emitted when every instruction in it is supported;
otherwise the reason is reported and the function is skipped.

Usage: lift.py OUT.c [ADDR ...]     (hex addresses; default: the prototype set)
       lift.py OUT.c --all-leaf     (every game-region leaf function)
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
MAX_BODY = 4000   # instructions; guards against runaway discovery


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
GPRS = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
MASK = {8: "0xFFu", 16: "0xFFFFu", 32: "0xFFFFFFFFu"}

COND = {
    x86.X86_INS_JO: "f.of", x86.X86_INS_JNO: "!f.of", x86.X86_INS_JB: "f.cf", x86.X86_INS_JAE: "!f.cf",
    x86.X86_INS_JE: "f.zf", x86.X86_INS_JNE: "!f.zf", x86.X86_INS_JBE: "(f.cf || f.zf)",
    x86.X86_INS_JA: "(!f.cf && !f.zf)", x86.X86_INS_JS: "f.sf", x86.X86_INS_JNS: "!f.sf",
    x86.X86_INS_JP: "f.pf", x86.X86_INS_JNP: "!f.pf", x86.X86_INS_JL: "(f.sf != f.of)",
    x86.X86_INS_JGE: "(f.sf == f.of)", x86.X86_INS_JLE: "(f.zf || f.sf != f.of)",
    x86.X86_INS_JG: "(!f.zf && f.sf == f.of)",
}
SETCC = {
    x86.X86_INS_SETO: "f.of", x86.X86_INS_SETNO: "!f.of", x86.X86_INS_SETB: "f.cf", x86.X86_INS_SETAE: "!f.cf",
    x86.X86_INS_SETE: "f.zf", x86.X86_INS_SETNE: "!f.zf", x86.X86_INS_SETBE: "(f.cf || f.zf)",
    x86.X86_INS_SETA: "(!f.cf && !f.zf)", x86.X86_INS_SETS: "f.sf", x86.X86_INS_SETNS: "!f.sf",
    x86.X86_INS_SETP: "f.pf", x86.X86_INS_SETNP: "!f.pf", x86.X86_INS_SETL: "(f.sf != f.of)",
    x86.X86_INS_SETGE: "(f.sf == f.of)", x86.X86_INS_SETLE: "(f.zf || f.sf != f.of)",
    x86.X86_INS_SETG: "(!f.zf && f.sf == f.of)",
}
FLAG_READERS = {x86.X86_INS_ADC, x86.X86_INS_SBB, x86.X86_INS_CMC, x86.X86_INS_RCL, x86.X86_INS_RCR,
                x86.X86_INS_PUSHF, x86.X86_INS_PUSHFD, x86.X86_INS_LAHF}
# Write every status flag the lifter models (CF ZF SF OF PF).
FLAG_WRITERS = {x86.X86_INS_ADD, x86.X86_INS_SUB, x86.X86_INS_CMP, x86.X86_INS_AND, x86.X86_INS_OR,
                x86.X86_INS_XOR, x86.X86_INS_TEST, x86.X86_INS_NEG}
BINARY = {x86.X86_INS_ADD: "add", x86.X86_INS_ADC: "add", x86.X86_INS_SUB: "sub", x86.X86_INS_SBB: "sub",
          x86.X86_INS_CMP: "sub", x86.X86_INS_AND: "&", x86.X86_INS_OR: "|", x86.X86_INS_XOR: "^",
          x86.X86_INS_TEST: "&"}
SHIFTS = {x86.X86_INS_SHL: "shl", x86.X86_INS_SAL: "shl", x86.X86_INS_SHR: "shr", x86.X86_INS_SAR: "sar",
          x86.X86_INS_ROL: "rol", x86.X86_INS_ROR: "ror"}


@dataclass
class Func:
    addr: int
    insns: dict[int, disasm.Insn] = field(default_factory=dict)
    targets: set[int] = field(default_factory=set)       # intra-function branch targets
    callees: set[int] = field(default_factory=set)


def collect(d: disasm.Disasm, f: int) -> Func:
    """Instructions reachable from f without following calls."""
    fn = Func(f)
    work = [f]
    while work:
        a = work.pop()
        while a not in fn.insns:
            ins = d.insns.get(a)
            if ins is None:
                raise Unsupported(f"undecoded code at {a:#x}")
            fn.insns[a] = ins
            if len(fn.insns) > MAX_BODY:
                raise Unsupported("body too large")
            if ins.id == x86.X86_INS_CALL:
                if ins.ops[0].type != x86.X86_OP_IMM:
                    raise Unsupported(f"indirect call at {a:#x}")
                fn.callees.add(ins.ops[0].imm & 0xFFFFFFFF)
            elif ins.id == x86.X86_INS_JMP or ins.id in disasm.COND_JUMPS:
                if ins.ops[0].type != x86.X86_OP_IMM:
                    raise Unsupported(f"indirect jump at {a:#x}")
                t = ins.ops[0].imm & 0xFFFFFFFF
                if t in d.func_starts and t != f:
                    if ins.id != x86.X86_INS_JMP:
                        raise Unsupported(f"conditional tail jump at {a:#x}")
                    fn.callees.add(t)        # tail call
                else:
                    fn.targets.add(t)
                    work.append(t)
            if disasm.Disasm._terminates(ins):
                break
            a = ins.end
    return fn


class Emitter:
    def __init__(self, fn: Func, d: disasm.Disasm):
        self.fn, self.d, self.out = fn, d, []

    # ---- operands -----------------------------------------------------------
    def reg_read(self, reg: int) -> tuple[str, int]:
        if reg not in REG:
            raise Unsupported(f"register {reg}")
        p, sh, bits = REG[reg]
        if bits == 32:
            return p, 32
        return (f"(({p} >> {sh}) & {MASK[bits]})" if sh else f"({p} & {MASK[bits]})"), bits

    def reg_write(self, reg: int, val: str) -> str:
        p, sh, bits = REG[reg]
        if bits == 32:
            return f"{p} = (uint32_t)({val});"
        m = int(MASK[bits][:-1], 16) << sh
        return f"{p} = ({p} & 0x{~m & 0xFFFFFFFF:X}u) | ((((uint32_t)({val})) & {MASK[bits]}) << {sh});"

    def addr(self, op) -> str:
        m = op.mem
        if m.segment not in (0, x86.X86_REG_DS, x86.X86_REG_SS):
            raise Unsupported("segment override")
        parts = []
        if m.base:
            parts.append(self.reg_read(m.base)[0])
        if m.index:
            idx = self.reg_read(m.index)[0]
            parts.append(f"{idx}*{m.scale}u" if m.scale != 1 else idx)
        if m.disp or not parts:
            parts.append(f"0x{m.disp & 0xFFFFFFFF:X}u")
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
    def leave(self) -> list[str]:
        return [f"c->r[{n.upper()}] = {n};" for n in GPRS] + ["return;"]

    def call(self, target: int, ret_addr: int | None) -> list[str]:
        if target not in self.fn.callees:
            raise Unsupported("call target")
        s = []
        if ret_addr is not None:
            s += ["esp -= 4;", f"wr32(c, esp, 0x{ret_addr:X}u);"]
        s += [f"c->r[{n.upper()}] = {n};" for n in GPRS]
        s += [f"f_{target:x}(c);"]
        if ret_addr is not None:     # tail calls return straight to our caller
            s += [f"if (c->ret_to != 0x{ret_addr:X}u) x86_stop(c, STOP_BADRET, c->ret_to);"]
        s += [f"{n} = c->r[{n.upper()}];" for n in GPRS]
        return s

    def check_flags_dead_after_call(self, call: disasm.Insn) -> None:
        """Flags live in C locals, so a callee's flags are lost on return.
        Refuse callers that read flags after a call before setting them."""
        a, seen = call.end, set()
        while a in self.fn.insns and a not in seen:
            seen.add(a)
            i = self.fn.insns[a]
            if i.id in COND or i.id in SETCC or i.id in FLAG_READERS:
                raise Unsupported(f"flags read after call at {a:#x}")
            if i.id in FLAG_WRITERS:
                return
            if i.id == x86.X86_INS_JMP and i.ops[0].type == x86.X86_OP_IMM:
                a = i.ops[0].imm & 0xFFFFFFFF
                continue
            if disasm.Disasm._terminates(i) or i.id == x86.X86_INS_CALL:
                return
            a = i.end

    def goto(self, src: int, t: int) -> list[str]:
        s = [f"x86_tick(c, 0x{src:X}u);"] if t <= src else []
        return s + [f"goto L_{t:x};"]

    # ---- instructions ------------------------------------------------------------
    def lift(self, i: disasm.Insn) -> list[str]:
        ops, iid = i.ops, i.id
        if i.prefix[0] in (x86.X86_PREFIX_REP, x86.X86_PREFIX_REPNE) and iid not in (x86.X86_INS_RET,):
            raise Unsupported(f"rep prefix: {i.mnemonic}")
        if iid in (x86.X86_INS_NOP,):
            return []
        if iid == x86.X86_INS_MOV:
            return [self.write(ops[0], self.read(ops[1], ops[0].size * 8))]
        if iid == x86.X86_INS_MOVZX:
            return [self.write(ops[0], self.read(ops[1]))]
        if iid == x86.X86_INS_MOVSX:
            sb = ops[1].size * 8
            st = {8: "int8_t", 16: "int16_t"}[sb]
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
                raise Unsupported("imul width")
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
            if ops[0].size != 4:
                raise Unsupported("16-bit push")
            return ["{", f"uint32_t t0 = {self.read(ops[0], 32)};", "esp -= 4;", "wr32(c, esp, t0);", "}"]
        if iid == x86.X86_INS_POP:
            if ops[0].size != 4:
                raise Unsupported("16-bit pop")
            # pop [esp+x] would use the incremented esp; handle registers only
            if ops[0].type != x86.X86_OP_REG:
                raise Unsupported("pop to memory")
            return ["{", "uint32_t t0 = rd32(c, esp);", "esp += 4;", self.write(ops[0], "t0"), "}"]
        if iid == x86.X86_INS_LEAVE:
            return ["esp = ebp;", "ebp = rd32(c, esp);", "esp += 4;"]
        if iid == x86.X86_INS_CLC:
            return ["f.cf = 0;"]
        if iid == x86.X86_INS_STC:
            return ["f.cf = 1;"]
        if iid == x86.X86_INS_CMC:
            return ["f.cf = !f.cf;"]
        if iid in COND:
            t = ops[0].imm & 0xFFFFFFFF
            return [f"if ({COND[iid].strip('()') if COND[iid].startswith('(') else COND[iid]}) {{", *self.goto(i.addr, t), "}"]
        if iid in (x86.X86_INS_JECXZ, x86.X86_INS_JCXZ):
            t = ops[0].imm & 0xFFFFFFFF
            reg = "ecx" if iid == x86.X86_INS_JECXZ else "(ecx & 0xFFFFu)"
            return [f"if ({reg} == 0) {{", *self.goto(i.addr, t), "}"]
        if iid == x86.X86_INS_LOOP:
            t = ops[0].imm & 0xFFFFFFFF
            return ["ecx -= 1;", "if (ecx != 0) {", *self.goto(i.addr, t), "}"]
        if iid == x86.X86_INS_JMP:
            t = ops[0].imm & 0xFFFFFFFF
            if t in self.fn.targets:
                return self.goto(i.addr, t)
            return self.call(t, None) + self.leave()        # tail call
        if iid == x86.X86_INS_CALL:
            self.check_flags_dead_after_call(i)
            return self.call(ops[0].imm & 0xFFFFFFFF, i.end)
        if iid == x86.X86_INS_RET:
            n = ops[0].imm if ops else 0
            return ["c->ret_to = rd32(c, esp);", f"esp += {4 + n}u;"] + self.leave()
        raise Unsupported(f"instruction {i.mnemonic} {i.op_str}")

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
        if op.size != 4:
            raise Unsupported("narrow div")
        src = self.read(op)
        if signed:
            return ["{", f"int32_t dv = (int32_t)({src});",
                    "int64_t dd = (int64_t)(((uint64_t)edx << 32) | eax);",
                    f"if (dv == 0) x86_stop(c, STOP_DIVIDE, 0x{i.addr:X}u);",
                    "int64_t q = dd / dv, r = dd % dv;",
                    f"if (q != (int32_t)q) x86_stop(c, STOP_DIVIDE, 0x{i.addr:X}u);",
                    "eax = (uint32_t)q; edx = (uint32_t)r;", "}"]
        return ["{", f"uint32_t dv = {src};", "uint64_t dd = ((uint64_t)edx << 32) | eax;",
                f"if (dv == 0) x86_stop(c, STOP_DIVIDE, 0x{i.addr:X}u);",
                "uint64_t q = dd / dv;",
                f"if (q >> 32) x86_stop(c, STOP_DIVIDE, 0x{i.addr:X}u);",
                "eax = (uint32_t)q; edx = (uint32_t)(dd % dv);", "}"]

    def emit(self) -> str:
        fn = self.fn
        body = []
        for a in sorted(fn.insns):
            i = fn.insns[a]
            lines = self.lift(i)
            label = f"L_{a:x}:" if a in fn.targets or a == fn.addr else ""
            body.append(f"{label} /* {a:08x}: {i.mnemonic} {i.op_str} */")
            body += ["    " + s for s in lines]
            # straight-line fall-through into the next decoded address is implicit,
            # but a gap (code reached only by jumps) needs an explicit goto.
            if not disasm.Disasm._terminates(i) and i.end not in fn.insns:
                raise Unsupported(f"falls through past body at {i.end:#x}")
            nxt = next((b for b in sorted(fn.insns) if b > a), None)
            if not disasm.Disasm._terminates(i) and nxt is not None and nxt != i.end:
                body.append(f"    goto L_{i.end:x};")
                fn.targets.add(i.end)
        head = [f"void f_{fn.addr:x}(Cpu *c) {{",
                "    " + " ".join(f"uint32_t {n} = c->r[{n.upper()}];" for n in GPRS),
                "    Flags f = {0};", "    (void)f;"]
        return "\n".join(head + body + ["}", ""])


def lift_functions(d: disasm.Disasm, roots: list[int]) -> tuple[dict[int, str], dict[int, str]]:
    """Lift roots and, transitively, their callees.  Returns (code, skipped-with-reason)."""
    done, skipped = {}, {}
    work = list(roots)
    while work:
        f = work.pop()
        if f in done or f in skipped:
            continue
        try:
            fn = collect(d, f)
            code = Emitter(fn, d).emit()
            # targets may grow during emit (explicit fall-through gotos); re-emit once
            code = Emitter(fn, d).emit()
        except Unsupported as e:
            skipped[f] = str(e)
            continue
        done[f] = code
        work += [t for t in fn.callees if t not in done]
    # drop functions whose callees could not be lifted
    changed = True
    while changed:
        changed = False
        for f in list(done):
            fn_callees = collect(d, f).callees
            bad = [t for t in fn_callees if t not in done]
            if bad:
                skipped[f] = f"callee {bad[0]:#x} not lifted"
                del done[f]
                changed = True
    return done, skipped


def leaf_game_functions(d: disasm.Disasm) -> list[int]:
    out = []
    for f in sorted(d.func_starts):
        if f >= analyze.REGION_SPLIT:
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
        "#pragma clang diagnostic ignored \"-Wunused-variable\"\n\n"
        f"{protos}\n\n" + "\n".join(funcs[a] for a in sorted(funcs)) +
        "\ntypedef struct { uint32_t addr; void (*fn)(Cpu *); } LiftedEntry;\n"
        f"const LiftedEntry lifted_table[] = {{\n{table}\n    {{0, 0}}\n}};\n"
    )


def main() -> None:
    out = pathlib.Path(sys.argv[1])
    args = sys.argv[2:]
    d = disasm.build(LEModule(DEFAULT_EXE.read_bytes()))
    if args == ["--all-leaf"]:
        roots = leaf_game_functions(d)
    else:
        roots = [int(a, 16) for a in args] or PROTOTYPE
    done, skipped = lift_functions(d, roots)
    write_c(out, done)
    print(f"lifted {len(done)} functions -> {out}")
    reasons = {}
    for f, why in skipped.items():
        reasons.setdefault(why.split(" at ")[0], []).append(f)
    for why, fs in sorted(reasons.items(), key=lambda x: -len(x[1])):
        print(f"  skipped {len(fs):4d}: {why}  e.g. {', '.join(hex(f) for f in fs[:4])}")


if __name__ == "__main__":
    main()
