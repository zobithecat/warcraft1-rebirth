"""Minimal loader for DOS/4GW Linear Executable (LE) files.

Parses the object table, page map and fixup records, then lays the objects
out at their preferred base addresses with all internal fixups applied.
Format reference: "IBM OS/2 16/32-bit Object Module Format (OMF) and Linear
eXecutable Module Format (LX)", plus the Watcom LE notes; LE differs from LX
in the page map entry layout and in storing the last page size at 0x2C.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Object flags
OBJ_READ, OBJ_WRITE, OBJ_EXEC = 0x1, 0x2, 0x4
OBJ_BIG = 0x2000  # 32-bit (USE32) object

# Fixup source types (low nibble of the source byte)
SRC_BYTE, SRC_SEL16, SRC_PTR1616, SRC_OFF16 = 0x0, 0x2, 0x3, 0x5
SRC_PTR1632, SRC_OFF32, SRC_REL32 = 0x6, 0x7, 0x8
SRC_SIZE = {SRC_BYTE: 1, SRC_SEL16: 2, SRC_PTR1616: 4, SRC_OFF16: 2,
            SRC_PTR1632: 6, SRC_OFF32: 4, SRC_REL32: 4}
SRC_NAMES = {SRC_BYTE: "byte", SRC_SEL16: "sel16", SRC_PTR1616: "ptr16:16",
             SRC_OFF16: "off16", SRC_PTR1632: "ptr16:32", SRC_OFF32: "off32",
             SRC_REL32: "rel32"}


@dataclass
class Obj:
    index: int          # 1-based
    vsize: int
    base: int
    flags: int
    page_index: int     # 1-based into the object page table
    page_count: int
    data: bytearray = field(default_factory=bytearray)

    @property
    def is_code(self) -> bool:
        return bool(self.flags & OBJ_EXEC)

    @property
    def end(self) -> int:
        return self.base + self.vsize

    def describe_flags(self) -> str:
        bits = [("R", OBJ_READ), ("W", OBJ_WRITE), ("X", OBJ_EXEC), ("32", OBJ_BIG)]
        return "".join(n for n, b in bits if self.flags & b)


@dataclass
class Fixup:
    src_type: int
    src_addr: int       # linear address of the patched bytes
    tgt_obj: int        # 1-based object number
    tgt_off: int        # offset within the target object (0 for sel16)

    @property
    def tgt_addr(self) -> int:
        return self.tgt_off  # resolved to linear by LEModule.fixup_target


class LEModule:
    def __init__(self, raw: bytes, bases: dict[int, int] | None = None):
        """`bases` overrides object load addresses ({object index: base}), e.g.
        to reproduce where DOS/4GW actually placed them at run time."""
        self.raw = raw
        self.bases = bases or {}
        if raw[:2] != b"MZ":
            raise ValueError("not an MZ executable")
        self.le_off = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[self.le_off:self.le_off + 2] != b"LE":
            raise ValueError("no LE header")
        self._parse_header()
        self._parse_objects()
        self._load_pages()
        self.fixups: list[Fixup] = []
        self._parse_fixups()
        self._apply_fixups()

    # ---- header -----------------------------------------------------------
    def _h(self, off: int, fmt: str = "<I") -> int:
        return struct.unpack_from(fmt, self.raw, self.le_off + off)[0]

    def _parse_header(self) -> None:
        self.page_count = self._h(0x14)
        self.eip_obj, self.eip = self._h(0x18), self._h(0x1C)
        self.esp_obj, self.esp = self._h(0x20), self._h(0x24)
        self.page_size = self._h(0x28)
        self.last_page_size = self._h(0x2C)
        self.obj_table_off = self._h(0x40)
        self.obj_count = self._h(0x44)
        self.page_table_off = self._h(0x48)
        self.fixup_page_off = self._h(0x68)
        self.fixup_rec_off = self._h(0x6C)
        self.import_mod_count = self._h(0x74)
        self.data_pages_off = self._h(0x80)          # absolute file offset
        self.debug_off, self.debug_len = self._h(0x98), self._h(0x9C)

    def _parse_objects(self) -> None:
        self.objects: list[Obj] = []
        base = self.le_off + self.obj_table_off
        for i in range(self.obj_count):
            vsize, rbase, flags, pidx, pcnt, _ = struct.unpack_from("<6I", self.raw, base + i * 24)
            self.objects.append(Obj(i + 1, vsize, self.bases.get(i + 1, rbase), flags, pidx, pcnt))

    def _page_file_offset(self, page: int) -> tuple[int, int]:
        """Return (file offset, size) of 1-based logical page `page`."""
        ent = self.raw[self.le_off + self.page_table_off + (page - 1) * 4:][:4]
        num = (ent[0] << 16) | (ent[1] << 8) | ent[2]
        if ent[3] != 0:
            raise NotImplementedError(f"page {page} has flags {ent[3]:#x}")
        size = self.last_page_size if num == self.page_count else self.page_size
        return self.data_pages_off + (num - 1) * self.page_size, size

    def _load_pages(self) -> None:
        for o in self.objects:
            buf = bytearray(max(o.vsize, o.page_count * self.page_size))
            for p in range(o.page_count):
                off, size = self._page_file_offset(o.page_index + p)
                buf[p * self.page_size:p * self.page_size + size] = self.raw[off:off + size]
            o.data = buf

    # ---- fixups -------------------------------------------------------------
    def _parse_fixups(self) -> None:
        r = self.raw
        fpt = self.le_off + self.fixup_page_off
        frt = self.le_off + self.fixup_rec_off
        for o in self.objects:
            for p in range(o.page_count):
                page = o.page_index + p
                start, end = struct.unpack_from("<II", r, fpt + (page - 1) * 4)
                pos, stop = frt + start, frt + end
                page_base = o.base + p * self.page_size
                while pos < stop:
                    src, flg = r[pos], r[pos + 1]
                    pos += 2
                    src_list = bool(src & 0x20)
                    if src_list:
                        count = r[pos]
                        pos += 1
                    else:
                        srcoff = struct.unpack_from("<h", r, pos)[0]
                        pos += 2
                    if flg & 0x3 != 0:
                        raise NotImplementedError(f"import/entry fixup (flags {flg:#x}) at page {page}")
                    if flg & 0x40:
                        tobj = struct.unpack_from("<H", r, pos)[0]
                        pos += 2
                    else:
                        tobj = r[pos]
                        pos += 1
                    stype = src & 0xF
                    toff = 0
                    if stype != SRC_SEL16:
                        if flg & 0x10:
                            toff = struct.unpack_from("<I", r, pos)[0]
                            pos += 4
                        else:
                            toff = struct.unpack_from("<H", r, pos)[0]
                            pos += 2
                    if flg & 0x04:
                        raise NotImplementedError("additive fixups")
                    if src_list:
                        offs = struct.unpack_from(f"<{count}h", r, pos)
                        pos += 2 * count
                    else:
                        offs = (srcoff,)
                    for so in offs:
                        self.fixups.append(Fixup(stype, page_base + so, tobj, toff))

    def obj(self, n: int) -> Obj:
        return self.objects[n - 1]

    def fixup_target(self, f: Fixup) -> int:
        # Watcom emits e.g. `base - 6` for array-minus-header pointers, so wrap.
        return (self.obj(f.tgt_obj).base + f.tgt_off) & 0xFFFFFFFF

    def _apply_fixups(self) -> None:
        for f in self.fixups:
            if f.src_type == SRC_SEL16:
                continue  # selectors are assigned at runtime; leave as-is
            o = self.obj_at(f.src_addr)
            if o is None:
                # Records may describe bytes that straddle into the next page/object.
                continue
            tgt = self.fixup_target(f)
            off = f.src_addr - o.base
            if f.src_type == SRC_OFF32:
                self._put(o, off, struct.pack("<I", tgt))
            elif f.src_type == SRC_REL32:
                self._put(o, off, struct.pack("<i", tgt - (f.src_addr + 4)))
            elif f.src_type == SRC_PTR1632:
                self._put(o, off, struct.pack("<I", tgt))
            elif f.src_type == SRC_OFF16:
                self._put(o, off, struct.pack("<H", tgt & 0xFFFF))
            else:
                raise NotImplementedError(f"fixup type {f.src_type:#x}")

    @staticmethod
    def _put(o: Obj, off: int, b: bytes) -> None:
        if off < 0:
            return
        o.data[off:off + len(b)] = b

    # ---- memory view ----------------------------------------------------------
    def obj_at(self, addr: int) -> Obj | None:
        for o in self.objects:
            if o.base <= addr < o.base + len(o.data):
                return o
        return None

    def read(self, addr: int, n: int) -> bytes:
        o = self.obj_at(addr)
        if o is None:
            raise KeyError(f"unmapped address {addr:#x}")
        off = addr - o.base
        return bytes(o.data[off:off + n])

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    @property
    def entry(self) -> int:
        return self.obj(self.eip_obj).base + self.eip
