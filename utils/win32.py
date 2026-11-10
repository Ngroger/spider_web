"""Windows subprocess helper — the ONLY place netsh / powershell are called.

Root cause of err_log.txt (29x repeat):
  netsh on RU Windows outputs in cp866 (OEM). subprocess.run(..., text=True)
  decodes with the locale encoding cp1251 -> UnicodeDecodeError in the
  reader thread, stdout becomes None, then .upper() on None -> warning spam
  on every 3-second tick.

Fix: capture BYTES, decode manually (cp866 -> utf-8 -> cp1251, errors=replace).
Never raises, never returns None. ASCII tokens like ON / OFF survive any
of those decodings, so firewall state parsing stays correct.
"""
from __future__ import annotations
import subprocess

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

def _decode(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("cp866", "utf-8", "cp1251"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")

def run_win_command(args: list[str], timeout: float = 8) -> tuple[int, str]:
    """Returns (returncode, stdout_text). Never raises, never returns None."""
    try:
        r = subprocess.run(
            args, capture_output=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW if CREATE_NO_WINDOW else 0,
        )
        return int(r.returncode), _decode(r.stdout or b"")
    except Exception:
        return -1, ""

def safe_upper(s) -> str:
    return (s or "").upper()
