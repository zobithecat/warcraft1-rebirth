#!/usr/bin/env python3
"""Capture real entry/exit states of war.exe functions from DOSBox-X.

Runs the game under the DOSBox-X debugger inside tmux, finds where DOS/4GW
loaded the LE objects, then for each target function records registers and a
16MB memory dump at entry and again when it returns to its caller.

Writes recomp/work/capture/<addr>_<n>.json (+ _in.bin / _out.bin).
Usage: capture.py [--per-func N] [--time S] ADDR ...   (image addresses)
"""
from __future__ import annotations

import argparse
import json
import re
import pathlib
import shutil
import struct
import subprocess
import time

import dbx
import disasm
import platform_map
from le import LEModule

ROOT = pathlib.Path(__file__).resolve().parents[1]
CAP = ROOT / "work" / "capture"
SESSION = "wc"
MEM = 0x1000000
REG_ORDER = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
BATCH = 25          # breakpoints per DOSBox run; BPLIST must fit on screen
TMUX_ROWS = 150


def prepare() -> None:
    """Game folder as INSTALL.EXE would leave it, plus the DOSBox-X config."""
    work = ROOT / "work"
    game = work / "game"
    if not (work / "cd").is_dir():
        raise SystemExit("run tools/extract.py first")
    game.mkdir(parents=True, exist_ok=True)
    for sub in ("DATA", "DRIVERS"):
        if not (game / sub).exists():
            shutil.copytree(work / "cd" / sub, game / sub)
    for src, dst in (("war.exe", "WAR.EXE"), ("dos4gw.exe", "DOS4GW.EXE")):
        shutil.copyfile(work / "exe" / src, game / dst)
    CAP.mkdir(parents=True, exist_ok=True)
    conf = (ROOT / "capture" / "dosbox.conf.in").read_text().replace("@GAMEDIR@", str(game))
    (CAP / "dosbox.conf").write_text(conf)


def start_dosbox() -> dbx.Debugger:
    prepare()
    subprocess.run(["tmux", "kill-session", "-t", SESSION], capture_output=True)
    exe = shutil.which("dosbox-x") or "/opt/homebrew/bin/dosbox-x"
    cmd = (f"cd {CAP} && SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy "
           f"{exe} -conf dosbox.conf -break-start -fastlaunch")
    subprocess.run(["tmux", "new-session", "-d", "-s", SESSION, "-x", "200", "-y", str(TMUX_ROWS), cmd], check=True)
    d = dbx.Debugger(SESSION)
    deadline = time.time() + 20
    while "I->" not in d.screen():
        if time.time() > deadline:
            raise TimeoutError("debugger prompt did not appear")
        time.sleep(0.3)
    return d


def mode13_site(mod: LEModule) -> int:
    """Image address of war.exe's `int 10h` with AX=0013h (set VGA mode 13h).

    DOS/4GW never sets video modes, so unlike the DOS/4GW check (int 21h
    AX=FF00h, which the extender itself issues hundreds of times) this
    breakpoint is reached after a handful of stops."""
    sites, _ = platform_map.scan(disasm.build(mod))
    hits = [int(s["addr"], 16) for s in sites if s["vector"] == "10h" and s["ax"] == "0x13"]
    if len(hits) != 1:
        raise RuntimeError(f"expected one mode-13h site, found {hits}")
    return hits[0]


def find_load_bases(d: dbx.Debugger, mod: LEModule) -> tuple[int, int, dict[int, int]]:
    """Break at war.exe's mode-13h call; return (CS, DS, {obj: base})."""
    site = mode13_site(mod)
    d.type("BPDEL *")
    d.type("BPINT 10 00 13")
    for _ in range(50):
        r = d.run_until_break(120)
        if r.mode == "Pr32":
            break
    else:
        raise RuntimeError("war.exe never set mode 13h from 32-bit code")
    cs, ds = r.seg["CS"], r.seg["DS"]
    code_delta = r.gpr["EIP"] - site
    d.type("BPDEL *")
    snap = dump(d, ds, "probe.bin")
    code = next(o for o in mod.objects if o.is_code)
    # Sanity: the instruction we stopped on really is war.exe's int 10h.
    if snap[site + code_delta:site + code_delta + 2] != bytes(code.data[site - code.base:site - code.base + 2]):
        raise RuntimeError("stopped at an int 10h that is not war.exe's mode-13h call")
    # The data delta follows from a relocated data pointer in the loaded code.
    deltas = {}
    for f in mod.fixups:
        if mod.obj_at(f.src_addr) is code and f.tgt_obj not in deltas:
            v = struct.unpack_from("<I", snap, f.src_addr + code_delta)[0]
            deltas[f.tgt_obj] = (v - mod.fixup_target(f)) & 0xFFFFFFFF
    deltas[code.index] = code_delta
    bases = {o.index: o.base + deltas[o.index] for o in mod.objects}
    # Every byte of the relocated code object must match the dump, except the
    # few variables the disassembler found being written inside code (e.g. the
    # CRT stores DS at 0x33438 during startup).
    placed = LEModule(mod.raw, bases).objects[code.index - 1]
    d_img = disasm.build(mod)
    writable = {t + k - code.base for t, refs in d_img.code_refs.items()
                if any(kind == "write" for _, kind in refs) for k in range(4)}
    bad = [i for i in range(placed.vsize)
           if i not in writable and snap[placed.base + i] != placed.data[i]]
    if bad:
        raise RuntimeError(f"relocated code object differs from DOSBox memory at {len(bad)} bytes, "
                           f"first image address {code.base + bad[0]:#x}")
    return cs, ds, bases


def dump(d: dbx.Debugger, ds: int, name: str) -> bytes:
    path = CAP / name.upper()       # DOSBox-X writes upper-case names
    path.unlink(missing_ok=True)
    d.type(f"MEMDUMPBIN {ds:X}:0 {MEM:X} {name}", settle=0.5)
    deadline = time.time() + 30
    while not (path.exists() and path.stat().st_size == MEM):
        if time.time() > deadline:
            raise TimeoutError(f"memory dump {name} not written")
        time.sleep(0.2)
    time.sleep(0.2)
    return path.read_bytes()


class Breakpoints:
    """Breakpoints kept in sync with the debugger by reading BPLIST.

    DOSBox-X numbers breakpoints by list position (newest first) and
    renumbers after a deletion, and fast typing can drop a command, so every
    change is checked against the list on screen.  Batches stay small enough
    (BATCH) for the whole list to fit in the output pane."""

    # Indices are hexadecimal ("09.", "0A.", ...) and so is BPDEL's argument.
    LINE = re.compile(r"^([0-9A-F]+)\. BP ([0-9A-F]{4}):([0-9A-F]+)\s*$")

    def __init__(self, d: dbx.Debugger, cs: int):
        self.d, self.cs = d, cs

    def listed(self) -> list[int]:
        """Breakpoint addresses in list order (index i == BPDEL i)."""
        self.d.type("BPLIST", settle=0.4)
        out = self.d.screen().split("Breakpoint list:")[-1]
        rows = {}
        for line in out.splitlines():
            m = self.LINE.match(line.strip())
            if m:
                rows[int(m.group(1), 16)] = int(m.group(3), 16)
        return [rows[i] for i in sorted(rows)]

    def ensure(self, addrs: set[int]) -> None:
        for _ in range(5):
            missing = addrs - set(self.listed())
            if not missing:
                return
            for a in missing:
                self.d.type(f"BP {self.cs:X}:{a:X}", settle=0.15)
        raise RuntimeError(f"could not set breakpoints {sorted(map(hex, missing))}")

    def add(self, addr: int) -> None:
        self.ensure({addr})

    def remove(self, addr: int) -> None:
        for _ in range(5):
            order = self.listed()
            if addr not in order:
                return
            self.d.type(f"BPDEL {order.index(addr):X}", settle=0.3)
        raise RuntimeError(f"could not delete breakpoint {addr:#x}")


def regs_list(r: dbx.Regs) -> list[int]:
    return [r.gpr[n] for n in REG_ORDER]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-func", type=int, default=3)
    ap.add_argument("--time", type=float, default=90, help="seconds to run the game per batch")
    ap.add_argument("--clean", action="store_true", help="delete earlier captures first")
    ap.add_argument("--capdir", help="write captures here instead of work/capture")
    ap.add_argument("--from-lifted", metavar="LIFTED_C",
                    help="target every function in a lift.py output (image-address build)")
    ap.add_argument("addrs", nargs="*")
    args = ap.parse_args()
    if args.from_lifted:
        table = pathlib.Path(args.from_lifted).read_text()
        args.addrs += re.findall(r"\{0x([0-9A-F]+)u, f_", table)
    if not args.addrs:
        ap.error("no target functions")

    global CAP
    if args.capdir:
        CAP = pathlib.Path(args.capdir).resolve()
    if args.clean and CAP.is_dir():
        for f in CAP.iterdir():
            if f.suffix.lower() in (".json", ".bin"):
                f.unlink()
    raw = (ROOT / "work" / "exe" / "war.exe").read_bytes()
    mod = LEModule(raw)
    targets = [int(a, 16) for a in args.addrs]
    counts = {}
    for b in range(0, len(targets), BATCH):
        batch = targets[b:b + BATCH]
        print(f"batch {b // BATCH + 1}/{(len(targets) + BATCH - 1) // BATCH}: {len(batch)} functions", flush=True)
        counts.update(capture_batch(mod, batch, args.per_func, args.time))
    hit = {f: n for f, n in counts.items() if n}
    print(f"captured {sum(hit.values())} states from {len(hit)} of {len(counts)} functions", flush=True)


def capture_batch(mod: LEModule, image_addrs: list[int], per_func: int, seconds: float) -> dict[int, int]:
    """Run the game once with breakpoints on `image_addrs`; return captures per function."""
    d = start_dosbox()
    try:
        cs, ds, bases = find_load_bases(d, mod)
        code_delta = bases[1] - mod.objects[0].base
        print(f"CS={cs:#x} DS={ds:#x} bases={ {k: hex(v) for k, v in bases.items()} }", flush=True)
        (CAP / "layout.json").write_text(json.dumps({"cs": cs, "ds": ds, "bases": bases}))
        want = {a + code_delta: 0 for a in image_addrs}
        bps = Breakpoints(d, cs)
        bps.ensure(set(want))
        deadline = time.time() + seconds
        while time.time() < deadline and any(n < per_func for n in want.values()):
            try:
                r = d.run_until_break(max(1, deadline - time.time()))
            except TimeoutError:
                break
            eip = r.gpr["EIP"]
            if eip not in want or r.mode != "Pr32" or want[eip] >= per_func:
                continue
            tag = f"{eip - code_delta:x}_{want[eip]}"
            mem_in = dump(d, ds, f"{tag}_in.bin")
            ret = struct.unpack_from("<I", mem_in, r.gpr["ESP"])[0]
            regs_in = regs_list(r)
            ret_was_target = ret in want
            bps.add(ret)
            out = d.run_until_break(60)
            while out.gpr["EIP"] != ret:      # another target hit first (e.g. an interrupt handler path)
                out = d.run_until_break(60)
            if not ret_was_target:
                bps.remove(ret)
            ok = out.gpr["ESP"] == regs_in[4] + 4
            mem_out = dump(d, ds, f"{tag}_out.bin")
            rec = {"func": eip - code_delta, "func_rt": eip, "ret": ret, "regs_in": regs_in,
                   "regs_out": regs_list(out), "returned_cleanly": ok, "bases": bases,
                   "in": f"{tag.upper()}_IN.BIN", "out": f"{tag.upper()}_OUT.BIN"}
            (CAP / f"{tag}.json").write_text(json.dumps(rec))
            want[eip] += 1
            print(f"captured {tag}: ret={ret:#x} clean={ok}", flush=True)
            if want[eip] >= per_func:
                bps.remove(eip)
        return {a - code_delta: n for a, n in want.items()}
    finally:
        subprocess.run(["tmux", "kill-session", "-t", SESSION], capture_output=True)


if __name__ == "__main__":
    main()
