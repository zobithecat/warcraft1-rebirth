#!/usr/bin/env python3
"""Lay out Worms (1995, DOS CD-ROM) from a raw dump of your own CD.

  extract.py [CUE]      default ../worms_team17/CDWORMS.cue, the .bin next to it

  CDWORMS.bin (+ .cue)
    track 1 (MODE1/2352)  -> work/worms.iso -> work/cd/     the D: drive
    tracks 2-9 (audio)    -> work/audio.json                where each track lies in the .bin
  work/game/                                                the C: drive, as SETUP/INSTALL leave it

Requires 7zz (brew install sevenzip).
"""
from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORK = ROOT / "work"
CUE = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT.parent / "worms_team17" / "CDWORMS.cue"
BIN = CUE.with_suffix(".bin")
RAW, DATA, HDR = 2352, 2048, 16
GAME_FILES = ["WORMS.EXE", "WRMS.EXE", "DOS4GW.EXE", "WORMS.CFG", "SETUP.EXE"]


def tracks() -> list[dict]:
    """(number, mode, first sector) for every track in the cue sheet."""
    out, cur = [], None
    for line in CUE.read_text().splitlines():
        m = re.match(r"\s*TRACK (\d+) (\S+)", line)
        if m:
            cur = {"track": int(m.group(1)), "mode": m.group(2)}
            out.append(cur)
        m = re.match(r"\s*INDEX 01 (\d+):(\d+):(\d+)", line)
        if m and cur is not None:
            mm, ss, ff = map(int, m.groups())
            cur["start"] = (mm * 60 + ss) * 75 + ff
    total = BIN.stat().st_size // RAW
    for t, nxt in zip(out, out[1:] + [None]):
        t["sectors"] = (nxt["start"] if nxt else total) - t["start"]
    return out


def main() -> None:
    if not BIN.exists():
        sys.exit(f"{BIN} not found")
    WORK.mkdir(parents=True, exist_ok=True)
    tr = tracks()
    data = tr[0]
    iso = WORK / "worms.iso"
    if not iso.exists():
        with BIN.open("rb") as f, iso.open("wb") as o:
            for _ in range(data["sectors"]):
                o.write(f.read(RAW)[HDR:HDR + DATA])
    exe = shutil.which("7zz") or shutil.which("7z")
    if not exe:
        sys.exit("7zz not found (brew install sevenzip)")
    subprocess.run([exe, "x", "-y", f"-o{WORK / 'cd'}", str(iso)], check=True, stdout=subprocess.DEVNULL)
    game = WORK / "game"
    game.mkdir(exist_ok=True)
    for name in GAME_FILES:
        shutil.copyfile(WORK / "cd" / name, game / name)
    audio = [{"track": t["track"], "start": t["start"], "sectors": t["sectors"]} for t in tr if t["mode"] == "AUDIO"]
    (WORK / "audio.json").write_text(json.dumps({"bin": str(BIN), "tracks": audio}, indent=1))
    print(f"data track: {data['sectors']} sectors -> {WORK / 'cd'}")
    print(f"audio tracks: {len(audio)}, {sum(t['sectors'] for t in audio) / 75 / 60:.1f} minutes")
    for p in sorted(game.iterdir()):
        print(f"  C:\\{p.name:12} {p.stat().st_size:>8}")


if __name__ == "__main__":
    main()
