#!/usr/bin/env python3
"""Check runtime/sound.c against the original game running in DOSBox-X.

DOSBox-X records the real thing with `DX-CAPTURE /A /O WAR.EXE` (a CONFIG.WAR
choosing AdLib, oplemu=nuked): a .wav and a .dro of every OPL register write
the game's own AIL ADLIB.MDI driver made.

  soundcmp.py dro2log capture.dro regs.log
      the .dro as "ms reg value" lines (for `soundtest regs`)
  soundcmp.py keyons capture.dro ours.log
      pair every key-on of the real driver with ours (pitch, timbre registers,
      time) and tally the volume register differences
  soundcmp.py wav reference.wav ours.wav
      align the two recordings and compare them frame by frame
"""
from __future__ import annotations

import collections
import struct
import sys
import wave

import numpy as np

SLOTS = [(0x00, 0x03), (0x01, 0x04), (0x02, 0x05), (0x08, 0x0B), (0x09, 0x0C),
         (0x0A, 0x0D), (0x10, 0x13), (0x11, 0x14), (0x12, 0x15)]


def read_dro(path: str) -> list[tuple[float, int, int]]:
    d = open(path, "rb").read()
    if d[:8] != b"DBRAWOPL" or struct.unpack_from("<H", d, 8)[0] != 2:
        raise SystemExit(f"{path}: not a DRO v2 capture")
    pairs = struct.unpack_from("<I", d, 12)[0]
    short_delay, long_delay, cml = d[23], d[24], d[25]
    codemap = d[26:26 + cml]
    pos, t, out = 26 + cml, 0.0, []
    for _ in range(pairs):
        r, v = d[pos], d[pos + 1]
        pos += 2
        if r == short_delay:
            t += v + 1
        elif r == long_delay:
            t += (v + 1) << 8
        else:
            out.append((t, codemap[r & 0x7F] | (0x100 if r & 0x80 else 0), v))
    return out


def read_log(path: str) -> list[tuple[float, int, int]]:
    out = []
    for line in open(path):
        if not line.startswith("#"):
            t, r, v = line.split()
            out.append((float(t), int(r, 16), int(v, 16)))
    return out


def keyons(writes):
    """State of the channel at every key-on: time, fnum, block, timbre registers, mod/car 0x40."""
    regs, key, ev = [0] * 256, [0] * 9, []
    for t, r, v in writes:
        if r > 0xFF:
            continue
        regs[r] = v
        if 0xB0 <= r <= 0xB8:
            ch = r - 0xB0
            k = v >> 5 & 1
            if k and not key[ch]:
                m, c = SLOTS[ch]
                timbre = (tuple(regs[b + m] for b in (0x20, 0x60, 0x80, 0xE0)) + (regs[0xC0 + ch],)
                          + tuple(regs[b + c] for b in (0x20, 0x60, 0x80, 0xE0)))
                ev.append((t, regs[0xA0 + ch] | (v & 3) << 8, v >> 2 & 7, timbre, regs[0x40 + m], regs[0x40 + c]))
            key[ch] = k
    return ev


def cmd_keyons(dro: str, log: str) -> None:
    a, b = keyons(read_dro(dro)), keyons(read_log(log))
    t0a, t0b = a[0][0], b[0][0]
    span = min(a[-1][0] - t0a, b[-1][0] - t0b)
    a = [e for e in a if e[0] - t0a <= span]
    b = [e for e in b if e[0] - t0b <= span]
    pool = collections.defaultdict(list)
    for e in b:
        pool[(e[1], e[2], e[3])].append(e)
    matched, diffs = 0, collections.Counter()
    for e in a:
        cands = pool[(e[1], e[2], e[3])]
        best = min(cands, key=lambda f: abs((f[0] - t0b) - (e[0] - t0a)), default=None)
        if best is None or abs((best[0] - t0b) - (e[0] - t0a)) > 60:
            continue
        cands.remove(best)
        matched += 1
        diffs[((best[5] & 63) - (e[5] & 63), (best[4] & 63) - (e[4] & 63))] += 1
    print(f"{span / 1000:.1f} s: reference {len(a)} key-ons, ours {len(b)}, "
          f"same pitch + timbre within 60 ms: {matched}")
    print("volume registers (carrier, modulator), ours - reference:", diffs.most_common(6))


def load_wav(path: str):
    w = wave.open(path)
    a = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).reshape(-1, w.getnchannels()).mean(axis=1)
    return a, w.getframerate()


def cmd_wav(ref_path: str, ours_path: str) -> None:
    ref, rate = load_wav(ref_path)
    ours, r2 = load_wav(ours_path)
    ours = np.interp(np.arange(0, len(ours) - 1, r2 / rate), np.arange(len(ours)), ours)
    on_r, on_o = int(np.argmax(np.abs(ref) > 50)), int(np.argmax(np.abs(ours) > 50))
    n, hop = 2048, 240

    def frames(x):
        f = np.log1p(np.array([np.abs(np.fft.rfft(x[i:i + n] * np.hanning(n)))[8:180]
                               for i in range(0, len(x) - n, hop)]))
        f -= f.mean(axis=1, keepdims=True)
        return f / (np.linalg.norm(f, axis=1, keepdims=True) + 1e-9)

    o = frames(ours[on_o:on_o + 12 * rate])
    r = frames(ref[max(0, on_r - rate // 2):on_r + 13 * rate])
    lag = max(range(0, 400), key=lambda k: (r[k:k + len(o)] * o[:len(r) - k]).sum(axis=1).mean())
    off = max(0, on_r - rate // 2) + lag * hop
    a, b = ref[off:off + 12 * rate], ours[on_o:on_o + 12 * rate]
    sim = (frames(a) * o).sum(axis=1)
    print(f"spectral frame similarity over 12 s: mean {sim.mean():.3f}")
    print(f"rms: reference {np.sqrt((a ** 2).mean()):.0f}, ours {np.sqrt((b ** 2).mean()):.0f}")
    fa, fb, hz = np.abs(np.fft.rfft(a)) ** 2, np.abs(np.fft.rfft(b)) ** 2, np.fft.rfftfreq(len(a), 1 / rate)
    for lo in (62, 125, 250, 500, 1000, 2000, 4000, 8000):
        m = (hz >= lo) & (hz < 2 * lo)
        print(f"  {lo:5d}-{2 * lo:5d} Hz: ours/reference {10 * np.log10(fb[m].sum() / fa[m].sum()):+.1f} dB")


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in ("dro2log", "keyons", "wav"):
        raise SystemExit(__doc__)
    cmd, x, y = sys.argv[1:]
    if cmd == "dro2log":
        with open(y, "w") as f:
            for t, r, v in read_dro(x):
                f.write(f"{t:.1f} {r:02x} {v:02x}\n")
    elif cmd == "keyons":
        cmd_keyons(x, y)
    else:
        cmd_wav(x, y)


if __name__ == "__main__":
    main()
