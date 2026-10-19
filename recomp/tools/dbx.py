"""Drive the DOSBox-X debugger running inside a tmux session.

The debugger is a curses UI; we type commands with `tmux send-keys` and read
the screen with `tmux capture-pane`.  Only the register panel, the code panel
and the output panel are parsed.
"""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass

REG_RE = re.compile(r"\b(EAX|EBX|ECX|EDX|ESI|EDI|EBP|ESP|EIP)=([0-9A-F]{8})")
SEG_RE = re.compile(r"\b(CS|DS|ES|FS|GS|SS)=([0-9A-F]{4})")
MODE_RE = re.compile(r"\b(Real|Pr16|Pr32|VM86)\b")
RUN_RE = re.compile(r"cc=\d+\s+(RUN|\w+)")


@dataclass
class Regs:
    gpr: dict[str, int]
    seg: dict[str, int]
    mode: str


class Debugger:
    def __init__(self, session: str):
        self.s = session

    def _tmux(self, *args: str) -> str:
        return subprocess.run(["tmux", *args], check=True, capture_output=True, text=True).stdout

    def screen(self) -> str:
        return self._tmux("capture-pane", "-t", self.s, "-p")

    def type(self, cmd: str, settle: float = 0.4) -> None:
        self._tmux("send-keys", "-t", self.s, cmd, "Enter")
        time.sleep(settle)

    def key(self, key: str, settle: float = 0.4) -> None:
        self._tmux("send-keys", "-t", self.s, key)
        time.sleep(settle)

    def regs(self) -> Regs:
        scr = self.screen()
        head = scr.split("Data view")[0]
        gpr = {k: int(v, 16) for k, v in REG_RE.findall(head)}
        seg = {k: int(v, 16) for k, v in SEG_RE.findall(head)}
        m = MODE_RE.search(head)
        return Regs(gpr, seg, m.group(1) if m else "?")

    def stopped_at(self) -> tuple[int, int] | None:
        """(CS, EIP) if the debugger is showing a stopped CPU, else None."""
        r = self.regs()
        if "EIP" not in r.gpr or "CS" not in r.seg:
            return None
        return r.seg["CS"], r.gpr["EIP"]

    def run_until_break(self, timeout: float = 60.0) -> Regs:
        """F5 (run), then wait until the debugger is back with a new stop location."""
        before = self.screen()
        self.key("F5", settle=0.5)
        deadline = time.time() + timeout
        while time.time() < deadline:
            scr = self.screen()
            if scr != before and "Register Overview" in scr and "I->" in scr:
                time.sleep(0.3)
                return self.regs()
            time.sleep(0.3)
        raise TimeoutError("debugger did not break")

    def output_tail(self, n: int = 10) -> list[str]:
        scr = self.screen().split("Output")[-1]
        return [l for l in scr.splitlines() if l.strip()][-n:]
