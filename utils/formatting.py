"""Formatting helpers: timestamps, durations, risk labels."""
from __future__ import annotations
from datetime import datetime, timezone

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def fmt_time(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z","+00:00"))
        return dt.astimezone().strftime("%H:%M:%S")
    except Exception:
        return str(iso)[:19]

def fmt_datetime(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z","+00:00"))
        return dt.astimezone().strftime("%d.%m.%Y %H:%M")
    except Exception:
        return str(iso)[:19]

RISK_ORDER = {"LOW":0,"MEDIUM":1,"HIGH":2}
def risk_rank(risk: str) -> int:
    return RISK_ORDER.get(str(risk).upper(), 0)
