#!/usr/bin/env python3
"""Pack captured RLE-blitter calls into a small frame file for the native viewer.

A capture is two 16MB memory dumps, but the blitter (0x1025C) only reads its
RLE source and the stack, and only writes its destination buffer.  Running
each capture once on Unicorn with memory hooks measures exactly which bytes
those are; only they go into the file, so the viewer (build/blitview) can
rebuild the guest memory the function needs without the dumps.

File layout (little-endian), "WCF1":
  u32 magic, count, func, code_lo, code_hi
  per frame:
    u32 regs_in[8], regs_out[8], ret
    u32 src_addr, src_len, dst_addr, dst_len
    u8  palette[768]            (6-bit VGA DAC values)
    u8  src[src_len]
    u8  dst_before[dst_len]
    u8  dst_after[dst_len]      (as DOSBox-X left it)

Usage: pack_frames.py CAPDIR OUT.wcf
"""
from __future__ import annotations

import json
import pathlib
import struct
import sys

from unicorn import UC_ARCH_X86, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MODE_32, Uc
from unicorn import x86_const as U

import replay

# The movie's palette chunk: the intro player uploads it from here after
# decoding (push 0x58C30 / push 0 / push 100h / call 0x3241C at 0x19105).
# Read from the exit dump: at entry it can still hold the previous scene's
# palette, which is what the DAC shadow at 0x61F80 shows.  Image address.
MOVIE_PALETTE_IMG = 0x58C30
STACK_SLACK = 64


def touched(rec: dict, mem: bytes) -> tuple[set[int], set[int]]:
    """Addresses read and written by one run of the function."""
    reads, writes = set(), set()
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0, replay.MEM)
    uc.mem_write(0, mem)
    uc.hook_add(UC_HOOK_MEM_READ, lambda uc, acc, a, size, v, d: reads.update(range(a, a + size)))
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda uc, acc, a, size, v, d: writes.update(range(a, a + size)))
    for reg, v in zip(replay.GPR_UC, rec["regs_in"]):
        uc.reg_write(reg, v)
    uc.emu_start(rec["func_rt"], rec["ret"])
    return reads, writes


def span(addrs: set[int]) -> tuple[int, int]:
    lo, hi = min(addrs), max(addrs) + 1
    return lo, hi - lo


def main() -> None:
    capdir, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    # capture order: <addr>_<n>.json
    recs = sorted((json.loads(p.read_text()) for p in capdir.glob("*_[0-9]*.json")),
                  key=lambda r: int(r["in"].split("_")[1]))
    if not recs:
        raise SystemExit(f"no captures in {capdir}")
    func = recs[0]["func_rt"]
    code = replay.code_range(recs[0]["bases"])
    frames = []
    for rec in recs:
        if rec["func_rt"] != func:
            raise SystemExit("captures of more than one function")
        mem_in = (capdir / rec["in"]).read_bytes()
        mem_out = (capdir / rec["out"]).read_bytes()
        reads, writes = touched(rec, mem_in)
        esp = rec["regs_in"][4]
        stack = set(range(esp - STACK_SLACK, esp + 8))
        src_addr, src_len = span(reads - stack - writes)
        dst_addr, dst_len = span(writes - stack)
        # Everything read must be in the packed source, destination or stack.
        covered = set(range(src_addr, src_addr + src_len)) | set(range(dst_addr, dst_addr + dst_len)) | stack
        if not reads <= covered:
            raise SystemExit(f"{rec['in']}: reads outside packed ranges")
        data_delta = int(rec["bases"]["2"]) - 0x50000
        pal_at = MOVIE_PALETTE_IMG + data_delta
        frames.append(
            struct.pack("<8I8II", *rec["regs_in"], *rec["regs_out"], rec["ret"])
            + struct.pack("<4I", src_addr, src_len, dst_addr, dst_len)
            + mem_out[pal_at:pal_at + 768]
            + mem_in[src_addr:src_addr + src_len]
            + mem_in[dst_addr:dst_addr + dst_len]
            + mem_out[dst_addr:dst_addr + dst_len])
        print(f"{rec['in']}: src {src_addr:#x}+{src_len}  dst {dst_addr:#x}+{dst_len}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(struct.pack("<5I", 0x31464357, len(frames), func, *code) + b"".join(frames))
    print(f"{len(frames)} frames -> {out} ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
