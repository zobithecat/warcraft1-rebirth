#!/usr/bin/env python3
"""Write war.exe's loaded memory image for the native runtime.

The objects are laid out at their preferred bases with all fixups applied,
exactly as lift.py assumes, and saved as one contiguous blob with a header:

  u32 magic "WIM1", entry, esp, base, size, code_lo, code_hi
  u8  image[size]          (guest memory from `base`)

Usage: mkimage.py OUT.bin [EXE] [--bases 1=0x10000,2=0x110000]
       (default: work/exe/war.exe at its preferred bases; pass the same
       --bases as lift.py when the objects are moved)
"""
from __future__ import annotations

import pathlib
import struct
import sys

from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> None:
    args = sys.argv[1:]
    bases = {}
    if "--bases" in args:
        i = args.index("--bases")
        bases = {int(k): int(v, 0) for k, v in (kv.split("=") for kv in args[i + 1].split(","))}
        del args[i:i + 2]
    out = pathlib.Path(args[0])
    exe = pathlib.Path(args[1]) if len(args) > 1 else ROOT / "work" / "exe" / "war.exe"
    mod = LEModule(exe.read_bytes(), bases)
    lo = min(o.base for o in mod.objects)
    hi = max(o.base + o.vsize for o in mod.objects)
    img = bytearray(hi - lo)
    for o in mod.objects:
        img[o.base - lo:o.base - lo + o.vsize] = o.data[:o.vsize]
    code = next(o for o in mod.objects if o.is_code)
    esp = mod.obj(mod.esp_obj).base + mod.esp
    out.write_bytes(struct.pack("<7I", 0x314D4957, mod.entry, esp, lo, len(img), code.base, code.end) + img)
    print(f"image {lo:#x}-{hi:#x} entry {mod.entry:#x} esp {esp:#x} -> {out}")


if __name__ == "__main__":
    main()
