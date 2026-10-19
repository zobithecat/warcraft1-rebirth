"""Recursive-descent disassembly of the code object of an LE module.

Seeds come from the entry point and from every relocated pointer that targets
the code object; switch tables (`jmp [reg*4 + table]`) are followed by reading
consecutive relocated dwords.  Everything decoded is kept in `Disasm.insns`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import capstone
from capstone import x86

from le import LEModule, Obj

COND_JUMPS = {
    x86.X86_INS_JA, x86.X86_INS_JAE, x86.X86_INS_JB, x86.X86_INS_JBE,
    x86.X86_INS_JCXZ, x86.X86_INS_JECXZ, x86.X86_INS_JE, x86.X86_INS_JG,
    x86.X86_INS_JGE, x86.X86_INS_JL, x86.X86_INS_JLE, x86.X86_INS_JNE,
    x86.X86_INS_JNO, x86.X86_INS_JNP, x86.X86_INS_JNS, x86.X86_INS_JO,
    x86.X86_INS_JP, x86.X86_INS_JS, x86.X86_INS_LOOP, x86.X86_INS_LOOPE,
    x86.X86_INS_LOOPNE,
}
MAX_SWITCH_BIAS = 64
MIN_STRING = 3
MIN_FALLTHROUGH_STRING = 8
STOPS = {x86.X86_INS_RET, x86.X86_INS_RETF, x86.X86_INS_IRET, x86.X86_INS_IRETD,
         x86.X86_INS_HLT, x86.X86_INS_UD2}


@dataclass
class Insn:
    addr: int
    size: int
    id: int
    mnemonic: str
    op_str: str
    ops: list            # capstone operand objects
    bytes: bytes
    prefix: list

    @property
    def end(self) -> int:
        return self.addr + self.size

    def __str__(self) -> str:
        return f"{self.addr:08x}  {self.bytes.hex():<20} {self.mnemonic} {self.op_str}"


@dataclass
class SwitchTable:
    jump_addr: int
    table_addr: int
    targets: list[int]


@dataclass
class Disasm:
    mod: LEModule
    code: Obj
    insns: dict[int, Insn] = field(default_factory=dict)
    covered: bytearray = field(default_factory=bytearray)   # 1 per byte decoded as code
    func_starts: set[int] = field(default_factory=set)
    labels: set[int] = field(default_factory=set)
    switch_tables: list[SwitchTable] = field(default_factory=list)
    table_bytes: set[int] = field(default_factory=set)       # addresses inside switch tables
    overlaps: list[int] = field(default_factory=list)        # decode conflicts
    # code address -> [(referencing insn, "imm" | "read" | "write")]
    code_refs: dict[int, list[tuple[int, str]]] = field(default_factory=dict)
    evicted: set[int] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.cs.detail = True
        self.covered = bytearray(self.code.vsize)
        self.fixup_at = {f.src_addr: f for f in self.mod.fixups}
        self.lo, self.hi = self.code.base, self.code.base + self.code.vsize

    # -- helpers -------------------------------------------------------------
    def in_code(self, a: int) -> bool:
        return self.lo <= a < self.hi

    def code_ptr_at(self, a: int) -> int | None:
        """Relocated code pointer stored at address `a`, if any."""
        f = self.fixup_at.get(a)
        if f and f.tgt_obj == self.code.index:
            return self.mod.fixup_target(f)
        return None

    def looks_like_string(self, a: int, min_len: int = MIN_STRING) -> bool:
        """Printable ASCII run ending in NUL: a string literal placed in code."""
        off = a - self.lo
        n = 0
        while off + n < len(self.code.data) and n < 256:
            c = self.code.data[off + n]
            if c == 0:
                return n >= min_len
            if not (0x20 <= c < 0x7F or c in (0x09, 0x0A, 0x0D)):
                return False
            n += 1
        return False

    def decode(self, a: int) -> Insn | None:
        off = a - self.lo
        raw = bytes(self.code.data[off:off + 16])
        for ci in self.cs.disasm(raw, a, 1):
            return Insn(ci.address, ci.size, ci.id, ci.mnemonic, ci.op_str,
                        list(ci.operands), bytes(ci.bytes), list(ci.prefix))
        return None

    # -- main walk -------------------------------------------------------------
    def run(self, seeds: list[tuple[int, bool]]) -> None:
        """seeds: (address, is_function)."""
        work = []
        for a, is_func in seeds:
            if self.in_code(a):
                (self.func_starts if is_func else self.labels).add(a)
                work.append(a)
        while work:
            a = work.pop()
            fallthrough = False
            while self.in_code(a) and a not in self.insns:
                if a in self.table_bytes:
                    self.overlaps.append(a)
                    break
                if self.covered[a - self.lo]:
                    # A branch target wins over bytes reached by fall-through
                    # (typically data after a call to a no-return function).
                    if fallthrough or not self._evict_covering(a):
                        self.overlaps.append(a)
                        break
                if fallthrough and self._looks_like_data(a):
                    break
                ins = self.decode(a)
                if ins is None:
                    break
                self.insns[a] = ins
                self._mark(ins, 1)
                for t, is_func in self._successors(ins):
                    if self.in_code(t):
                        (self.func_starts if is_func else self.labels).add(t)
                        work.append(t)
                if self._terminates(ins):
                    break
                a = ins.end
                fallthrough = True

    def _mark(self, ins: Insn, v: int) -> None:
        for i in range(ins.size):
            if ins.addr + i < self.hi:
                self.covered[ins.addr + i - self.lo] = v

    def _evict_covering(self, a: int) -> bool:
        """Drop the instruction straddling `a`, unless it is itself a branch target."""
        for b in range(a - 1, max(self.lo, a - 16) - 1, -1):
            ins = self.insns.get(b)
            if ins is None:
                continue
            if ins.end <= a or b in self.func_starts or b in self.labels or b in self.evicted:
                return False
            del self.insns[b]
            self._mark(ins, 0)
            self.evicted.add(b)
            # The misaligned fall-through chain after it goes too; the
            # realigned stream re-decodes whatever is really there.
            e = ins.end
            while e in self.insns and e not in self.func_starts and e not in self.labels:
                nxt = self.insns.pop(e)
                self._mark(nxt, 0)
                if self._terminates(nxt):
                    break
                e = nxt.end
            return True
        return False

    def _looks_like_data(self, a: int) -> bool:
        # `add [eax], al` (00 00) does not occur in compiled code but zero
        # padding/tables do.  Only long strings count: short printable runs
        # are common in real code (66 3d 40 00 = "f=@\0").
        off = a - self.lo
        return self.code.data[off:off + 2] == b"\x00\x00" or self.looks_like_string(a, MIN_FALLTHROUGH_STRING)

    def _imm_target(self, ins: Insn) -> int | None:
        if ins.ops and ins.ops[0].type == x86.X86_OP_IMM:
            return ins.ops[0].imm & 0xFFFFFFFF
        return None

    def _successors(self, ins: Insn):
        if ins.id == x86.X86_INS_CALL:
            t = self._imm_target(ins)
            if t is not None:
                yield t, True
        elif ins.id == x86.X86_INS_JMP or ins.id in COND_JUMPS:
            t = self._imm_target(ins)
            if t is not None:
                yield t, False
            elif ins.id == x86.X86_INS_JMP:
                yield from ((t, False) for t in self._switch(ins))
        # Relocated code addresses embedded in operands: an immediate is usually
        # a code pointer (push offset f / mov [x], offset f) but can also be the
        # address of a string or table kept in code; a memory displacement is
        # data in code, or self-modifying code if written.  Only recorded here;
        # build() decides in its second pass once all references are known.
        for k in range(ins.size - 3):
            t = self.code_ptr_at(ins.addr + k)
            if t is None:
                continue
            kind = self._operand_kind(ins, t)
            if kind == "imm" and self.looks_like_string(t):
                kind = "string"
            self.code_refs.setdefault(t, []).append((ins.addr, kind))

    @staticmethod
    def _operand_kind(ins: Insn, value: int) -> str:
        for op in ins.ops:
            if op.type == x86.X86_OP_IMM and op.imm & 0xFFFFFFFF == value:
                return "imm"
        for op in ins.ops:
            if op.type == x86.X86_OP_MEM:
                if op.access & capstone.CS_AC_WRITE:
                    return "write"
                return "read"
        return "imm"

    def _switch(self, ins: Insn) -> list[int]:
        """Follow `jmp [idx*4 + table]` and `jmp [preScaledIdx + table]`."""
        op = ins.ops[0]
        if op.type != x86.X86_OP_MEM:
            return []
        scaled = op.mem.base == 0 and op.mem.scale == 4
        prescaled = op.mem.index == 0 and op.mem.base != 0
        if not (scaled or prescaled):
            return []
        disp = op.mem.disp & 0xFFFFFFFF
        if not self.in_code(disp) and not self.mod.obj_at(disp):
            return []
        # Watcom biases the displacement by -min_case*4, so the first entry
        # may sit a little after the displacement.
        table = next((disp + k for k in range(0, 4 * MAX_SWITCH_BIAS, 4)
                      if self.code_ptr_at(disp + k) is not None), None)
        if table is None:
            return []
        targets, a = [], table
        while (t := self.code_ptr_at(a)) is not None:
            targets.append(t)
            self.table_bytes.update(range(a, a + 4))
            a += 4
        if targets:
            self.switch_tables.append(SwitchTable(ins.addr, table, targets))
        return targets

    @staticmethod
    def _terminates(ins: Insn) -> bool:
        return ins.id in STOPS or ins.id == x86.X86_INS_JMP

    # -- results -----------------------------------------------------------------
    def coverage(self) -> float:
        return sum(self.covered) / len(self.covered)

    def gaps(self) -> list[tuple[int, int]]:
        """Undecoded [start, end) ranges that are not switch tables."""
        out, start = [], None
        for i, c in enumerate(self.covered):
            a = self.lo + i
            hole = not c and a not in self.table_bytes
            if hole and start is None:
                start = a
            elif not hole and start is not None:
                out.append((start, a))
                start = None
        if start is not None:
            out.append((start, self.hi))
        return out

    def sorted_insns(self) -> list[Insn]:
        return [self.insns[a] for a in sorted(self.insns)]


def build(mod: LEModule) -> Disasm:
    code = next(o for o in mod.objects if o.is_code)
    d = Disasm(mod, code)
    seeds: list[tuple[int, bool]] = [(mod.entry, True)]
    # Code pointers stored in data objects are callback / dispatch targets.
    for f in mod.fixups:
        src = mod.obj_at(f.src_addr)
        if f.tgt_obj == code.index and src is not None and not src.is_code:
            seeds.append((mod.fixup_target(f), True))
    d.run(seeds)
    d.pass1_insns = len(d.insns)
    # Second pass: every relocated pointer into code is a real code address
    # unless it points at data kept in code (a pointer table, a string, a
    # dereferenced variable or SMC slot).  This picks up function pointers
    # taken as immediates, code only referenced from not-yet-reached code and
    # switch tables nobody points at directly.  Iterate since newly decoded
    # code adds references and switches claim more table bytes.
    fixup_srcs = set(d.fixup_at)
    while True:
        before = len(d.insns)
        extra = []
        for f in mod.fixups:
            t = mod.fixup_target(f)
            if f.tgt_obj != code.index or t in d.insns or t in fixup_srcs or t in d.table_bytes:
                continue
            refs = d.code_refs.get(t, ())
            if any(kind != "imm" for _, kind in refs) or d.looks_like_string(t):
                continue
            extra.append((t, bool(refs)))
        d.run(extra)
        if len(d.insns) == before:
            break
    return d
