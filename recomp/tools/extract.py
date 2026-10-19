#!/usr/bin/env python3
"""Extract war.exe (and friends) from the raw CD dump.

CD_DIC/WARCRAFT.bin (MODE1/2352) -> work/WARCRAFT.iso -> *.EXA (LHA) -> work/exe/
Requires 7zz (brew install sevenzip).
"""
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORK = ROOT / "recomp" / "work"
BIN = ROOT / "CD_DIC" / "WARCRAFT.bin"
SECTOR_RAW, SECTOR_DATA, SECTOR_HDR = 2352, 2048, 16
EXA_FILES = ["WAR.EXA", "DOS4GW.EXA", "SETUP.EXA"]


def bin_to_iso(src: pathlib.Path, dst: pathlib.Path) -> None:
    with src.open("rb") as f, dst.open("wb") as o:
        while sector := f.read(SECTOR_RAW):
            if len(sector) != SECTOR_RAW:
                sys.exit(f"truncated sector in {src}")
            o.write(sector[SECTOR_HDR:SECTOR_HDR + SECTOR_DATA])


def run_7z(*args: str) -> None:
    exe = shutil.which("7zz") or shutil.which("7z")
    if not exe:
        sys.exit("7zz not found (brew install sevenzip)")
    subprocess.run([exe, *args], check=True, stdout=subprocess.DEVNULL)


def main() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    iso = WORK / "WARCRAFT.iso"
    if not iso.exists():
        bin_to_iso(BIN, iso)
    cd = WORK / "cd"
    run_7z("x", "-y", f"-o{cd}", str(iso))
    exe_dir = WORK / "exe"
    for name in EXA_FILES:
        run_7z("x", "-y", f"-o{exe_dir}", str(cd / name))
    for p in sorted(exe_dir.iterdir()):
        print(f"{p.name:16} {p.stat().st_size:>8}")


if __name__ == "__main__":
    main()
