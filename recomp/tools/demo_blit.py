#!/usr/bin/env python3
"""Visual demo: run war.exe's RLE blitter (0x1025C), lifted to arm64, on a
real game state captured from DOSBox-X, and draw the result next to what
DOSBox itself produced.

Writes recomp/work/demo/blit_<capture>.png and prints timings.
Usage: demo_blit.py [CAPTURE_TAG]   (default: the first 1025c capture)
"""
from __future__ import annotations

import ctypes
import json
import pathlib
import sys
import time

from PIL import Image, ImageDraw

import replay

ROOT = pathlib.Path(__file__).resolve().parents[1]
CAP = ROOT / "work" / "capture"
OUT = ROOT / "work" / "demo"
# The game's 256-colour palette table (pushed whole to the palette setter at
# 0x19105: push 0x58C30 / push 0 / push 100h / call 0x3241C).  Image address.
PALETTE_IMG = 0x58C30
VGA = 0xA0000
SCALE = 2
TIMING_RUNS = 200


def palette(mem: bytes, data_delta: int) -> list[tuple[int, int, int]]:
    a = PALETTE_IMG + data_delta
    raw = mem[a:a + 768]
    return [tuple(min(255, v * 255 // 63) for v in raw[i:i + 3]) for i in range(0, 768, 3)]


def picture(mem: bytes, base: int, width: int, height: int, pal) -> Image.Image:
    img = Image.new("RGB", (width, height))
    img.putdata([pal[b] for b in mem[base:base + width * height]])
    return img.resize((width * SCALE, height * SCALE), Image.NEAREST)


def main() -> None:
    tag = sys.argv[1] if len(sys.argv) > 1 else sorted(p.stem for p in CAP.glob("1025*_[0-9].json"))[0]
    rec = json.loads((CAP / f"{tag}.json").read_text())
    mem_in = (CAP / rec["in"]).read_bytes()
    mem_dos = (CAP / rec["out"]).read_bytes()
    bases = {int(k): v for k, v in rec["bases"].items()}
    data_delta = bases[2] - 0x50000
    code = replay.code_range(rec["bases"])

    lib = ctypes.CDLL(str(ROOT / "build" / "liblifted_rt.dylib"))
    lib.lifted_run.restype = ctypes.c_int
    lib.lifted_run.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p, ctypes.c_uint32,
                               ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int64, ctypes.POINTER(ctypes.c_uint32)]

    # One native call on the captured state, plus a timing loop on fresh copies.
    status, regs, mem_arm = replay.run_lifted(lib, rec, mem_in, code)
    buf = ctypes.create_string_buffer(mem_in, replay.MEM)
    regs0 = (ctypes.c_uint32 * 8)(*rec["regs_in"])
    fault = ctypes.c_uint32()
    t_native = 0.0
    for _ in range(TIMING_RUNS):
        ctypes.memmove(regs0, (ctypes.c_uint32 * 8)(*rec["regs_in"]), 32)
        ctypes.memmove(buf, mem_in, replay.MEM)
        t0 = time.perf_counter()
        lib.lifted_run(rec["func_rt"], regs0, buf, replay.MEM, code[0], code[1], replay.BUDGET, ctypes.byref(fault))
        t_native += time.perf_counter() - t0
    t0 = time.perf_counter()
    u_status, u_regs, mem_uc = replay.run_unicorn(rec, mem_in, code)
    t_unicorn = time.perf_counter() - t0

    dest, width, rows = rec["regs_in"][0], rec["regs_in"][1], rec["regs_in"][3]
    pal = palette(mem_in, data_delta)
    panels = [
        ("before the call (buffer)", picture(mem_in, dest, width, rows, pal)),
        ("after: DOSBox-X (real x86 run)", picture(mem_dos, dest, width, rows, pal)),
        ("after: lifted C, native arm64", picture(mem_arm, dest, width, rows, pal)),
    ]
    same = mem_arm[dest:dest + width * rows] == mem_dos[dest:dest + width * rows]
    diff_px = sum(1 for a, b in zip(mem_arm[dest:dest + width * rows], mem_dos[dest:dest + width * rows]) if a != b)

    pad, label_h = 12, 22
    w = panels[0][1].width
    h = panels[0][1].height
    sheet = Image.new("RGB", (pad + len(panels) * (w + pad), label_h + h + pad * 2), (24, 24, 28))
    draw = ImageDraw.Draw(sheet)
    for i, (label, img) in enumerate(panels):
        x = pad + i * (w + pad)
        draw.text((x, pad // 2), label, fill=(230, 230, 230))
        sheet.paste(img, (x, label_h + pad // 2))
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"blit_{tag}.png"
    sheet.save(path)

    print(f"capture {tag}: blitter f_{rec['func']:x} at run-time {rec['func_rt']:#x}")
    print(f"  dest {dest:#x}  src {rec['regs_in'][2]:#x}  {width}x{rows} pixels")
    print(f"  native arm64: status={status}  {t_native / TIMING_RUNS * 1e6:.1f} us/call (mean of {TIMING_RUNS})")
    print(f"  unicorn x86 : status={u_status}  {t_unicorn * 1e3:.1f} ms/call")
    print(f"  buffer arm64 == DOSBox: {same}  (differing pixels: {diff_px})")
    print(f"  registers arm64 == DOSBox: {regs == rec['regs_out']}")
    print(f"  wrote {path}")


if __name__ == "__main__":
    main()
