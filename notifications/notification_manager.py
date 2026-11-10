"""Consolidated notification logic — spec §6, FR-18..28.
Pure logic, no Qt: decides SHOULD we notify, dedups, groups, applies sensitivity.
UI layer only renders what this returns.

Fix #4 (fresh-only): connections that already existed when the firewall
started (baseline) never notify. Caller (MainWindow._tick) only feeds
NEW (pid, ip, port) keys; this class double-checks via is_preexisting().

Fix #5 (system): is_system_exe() — svchost / System / Registry / lsass /
anything in C:\\Windows\\System32 etc. is Windows itself. Such traffic is
allowed silently, never notified, never shown as user traffic.
"""
from __future__ import annotations
import time
from app.constants import SYSTEM_EXES, SYSTEM_PATHS, TRUSTED_BROWSERS
from utils.network_utils import is_loopback, is_external_ip, is_suspicious_port
from utils.formatting import now_iso
from storage.models import NotificationGroup

def is_system_exe(exe_name: str | None, exe_path: str | None = None) -> bool:
    """True if this is Windows itself, not a user app."""
    n = (exe_name or "").strip().lower()
    if not n:
        return False
    if n in SYSTEM_EXES:
        return True
    # PID 4 / no exe + name "System" is the kernel
    if n in ("system", "registry", "memcompression", "secure system"):
        return True
    path = (exe_path or "").lower().replace("/", "\\")
    if path:
        for sp in SYSTEM_PATHS:
            if sp in path:
                return True
        # C:\Windows\... without System32 is still Windows in most cases,
        # but keep it narrow: only System32/SysWOW64/WinSxS count (above).
    return False

class NotificationManager:
    def __init__(self, config=None, trusted_apps: list | None = None):
        self.config = config
        self.trusted_apps = set((trusted_apps or []))
        self._seen: dict[tuple, float] = {}
        self._groups: dict[str, NotificationGroup] = {}
        self.history: list[NotificationGroup] = []
        self.sensitivity = "Balanced"
        self.dedup_window = 300
        self.session_start: float = 0.0
        self.baseline_keys: set = set()
    def set_session_start(self, ts: float):
        self.session_start = float(ts or 0.0)
    def set_baseline(self, keys):
        self.baseline_keys = set(keys or set())
    def is_preexisting(self, pid, remote_ip, remote_port, proto=None) -> bool:
        if not self.baseline_keys:
            return False
        if proto is not None:
            return (pid, remote_ip, remote_port, proto) in self.baseline_keys
        return any(k[0] == pid and k[1] == remote_ip and k[2] == remote_port for k in self.baseline_keys)
    def set_sensitivity(self, mode: str):
        if mode in ("Minimal", "Balanced", "Strict"): self.sensitivity = mode
    def is_trusted(self, exe_name: str | None, exe_path: str | None = None) -> bool:
        if not exe_name: return False
        n = exe_name.lower()
        if n in SYSTEM_EXES: return True
        if (exe_path or "").lower() in self.trusted_apps: return True
        if n in self.trusted_apps: return True
        return False
    def should_notify(self, *, app_name, exe_name=None, exe_path=None, remote_ip=None, remote_port=None,
                      direction="OUTBOUND", risk="LOW", is_system=False, is_trusted_app=False,
                      pid=None, proto=None) -> tuple[bool, str]:
        """External-request-only policy (Table 11). Returns (notify, reason)."""
        # Fix #5: system traffic never notifies — no matter the risk/port.
        if is_system or is_system_exe(exe_name, exe_path):
            return False, "System app — suppressed"
        # Fix #4: already-connected at firewall startup — not a fresh request.
        if pid is not None and self.is_preexisting(pid, remote_ip, remote_port, proto):
            return False, "Already connected before firewall started"
        if is_loopback(remote_ip): return False, "Loopback — no notification"
        if is_trusted_app and risk == "LOW" and not is_suspicious_port(remote_port):
            return False, "Trusted app, low risk — silent"
        if not is_external_ip(remote_ip) and risk == "LOW":
            if self.sensitivity == "Strict": return True, "Strict: LAN traffic from unknown app"
            return False, "LAN / private traffic, low risk — silent"
        if self.sensitivity == "Minimal":
            return (risk == "HIGH"), "Minimal: only high-risk alerts"
        if self.sensitivity == "Balanced":
            return (risk in ("MEDIUM", "HIGH")), "Balanced: medium/high alerts"
        return True, "Strict: all external requests"
    @staticmethod
    def assess_risk(*, app_name, exe_name=None, remote_ip=None, remote_port=None, direction="OUTBOUND",
                    is_unknown=False, is_system=False) -> str:
        if is_system or is_system_exe(exe_name):
            return "LOW"
        if direction == "INBOUND" and is_unknown: return "HIGH"
        if is_suspicious_port(remote_port): return "HIGH"
        if is_unknown and is_external_ip(remote_ip): return "MEDIUM"
        return "LOW"
    def is_duplicate(self, app: str, destination: str, session: str = "default") -> bool:
        key = (app.lower(), destination, session)
        now = time.time()
        last = self._seen.get(key, 0)
        if now - last < self.dedup_window: return True
        self._seen[key] = now
        return False
    def create_group(self, *, origin_application, origin_pid=None, related_processes=None,
                     connections=None, direction="OUTBOUND", risk="LOW") -> NotificationGroup:
        g = NotificationGroup(origin_application=origin_application, origin_pid=origin_pid,
            related_processes=related_processes or [], connections=connections or [],
            direction=direction, risk_level=risk, status="PENDING", created_at=now_iso())
        self._groups[g.group_id] = g; self.history.append(g)
        return g
    def resolve_group(self, group_id: str, decision: str) -> NotificationGroup | None:
        g = self._groups.get(group_id)
        if g: g.status = decision
        return g
    def pending(self) -> list[NotificationGroup]:
        return [g for g in self.history if g.status == "PENDING"]
