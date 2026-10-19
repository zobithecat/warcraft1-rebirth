#!/usr/bin/env python3
"""Regression checks for platform_map.py against facts traced by hand in war.lst.

Each expectation below was read directly off the disassembly (addresses in
comments) before the tool could resolve it, so the tool is checked against
independent evidence rather than against its own earlier output.
Usage: test_platform_map.py [war.exe]
"""
from __future__ import annotations

import pathlib
import sys

import disasm
import platform_map as pm
from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]

# (site, field, expected)
EXPECT_INSTALLS = [
    # 0x30ba4: regs.w.ax = 2509h, edx = 0x308f0, int386x(0x21, ...)  -> keyboard ISR
    ("0x30c16", "api", "DOS 25h set vector"), ("0x30c16", "vector", "09h"), ("0x30c16", "handler", "0x308f0"),
    # 0x374d7: mov eax, 8 / mov edx, 0x3734e / mov ah, 0x25 / int 21h   -> AIL timer ISR
    ("0x375fc", "api", "DOS 25h set vector"), ("0x375fc", "vector", "08h"), ("0x375fc", "handler", "0x3734e"),
    # 0x30c78: regs.w.ax = 0Ch, regs.w.cx = 1Fh, edx = 0x30820, int386x(0x33, ...) -> mouse callback
    ("0x30cec", "api", "mouse 0Ch event handler"), ("0x30cec", "handler", "0x30820"),
    # 0x3c886: mov edx, 0x3c418 / mov ax, 0205h / mov bl, 23h / int 31h -> CRT Ctrl-C handler
    ("0x3c916", "api", "DPMI set PM vector"), ("0x3c916", "vector", "23h"), ("0x3c916", "handler", "0x3c418"),
    # 0x3c886: mov cl, 23h / mov edx, 0x3c418 / mov ax, 2502h / int 21h -> Phar Lap branch
    ("0x3c9b6", "api", "PharLap 2502h"), ("0x3c9b6", "vector", "23h"),
]
EXPECT_SITES = [
    # 0x3afc3: regs.h.ah = 2Ch; intdos(&regs, &regs)  -> clock() time source
    ("0x3afd1", "via", "regs@3f9d8"), ("0x3afd1", "vector", "21h"), ("0x3afd1", "ah", "0x2c"),
]
EXPECT_PORTS = [
    ("0x30911", "inp", "0x60"),    # keyboard ISR: mov eax, 60h / call inp
    ("0x3242a", "out", "0x3c8"),   # palette: mov dx, 3C8h / out dx, al
    ("0x3747e", "out", "0x43"),    # PIT mode
]
EXPECT_WRAPPERS = {0x3F9D8: ("eax", 0x21)}   # intdos(): REGS* in eax, int 21h; nothing else


def main() -> None:
    exe = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "work" / "exe" / "war.exe"
    d = disasm.build(LEModule(exe.read_bytes()))
    ints, ports = pm.scan(d)
    by_addr = {s["addr"]: s for s in ints}
    port_by = {p["addr"]: p for p in ports}
    fails = []

    for addr, key, want in EXPECT_INSTALLS:
        got = by_addr.get(addr, {}).get("install", {}).get(key)
        if got != want:
            fails.append(f"install {addr}.{key}: want {want!r}, got {got!r}")
    for addr, key, want in EXPECT_SITES:
        got = by_addr.get(addr, {}).get(key)
        if got != want:
            fails.append(f"site {addr}.{key}: want {want!r}, got {got!r}")
    for addr, via, port in EXPECT_PORTS:
        p = port_by.get(addr, {})
        if (p.get("via"), p.get("port")) != (via, port):
            fails.append(f"port {addr}: want {via} {port}, got {p.get('via')} {p.get('port')}")
    wrappers = pm.find_regs_wrappers(d)
    if wrappers != EXPECT_WRAPPERS:
        fails.append(f"REGS wrappers: want {EXPECT_WRAPPERS}, got { {hex(k): v for k, v in wrappers.items()} }")

    total = len(EXPECT_INSTALLS) + len(EXPECT_SITES) + len(EXPECT_PORTS) + 1
    for f in fails:
        print("FAIL", f)
    print(f"{total - len(fails)}/{total} passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
