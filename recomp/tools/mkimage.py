#!/usr/bin/env python3
"""Write war.exe's loaded memory image for the native runtime.

The objects are laid out at their preferred bases with all fixups applied,
exactly as lift.py assumes, and saved as one contiguous blob with a header:

  u32 magic "WIM1", entry, esp, base, size, code_lo, code_hi
  u8  image[size]          (guest memory from `base`)

Usage: mkimage.py OUT.bin [war.exe]
"""
from __future__ import annotations

import pathlib
import struct
import sys

from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> None:
    out = pathlib.Path(sys.argv[1])
    exe = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "work" / "exe" / "war.exe"
    mod = LEModule(exe.read_bytes())
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
