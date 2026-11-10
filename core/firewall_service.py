"""Firewall service — spec §5.1, FR-01..08.
Windows: netsh advfirewall (supported API, no kernel driver).
Non-Windows / no-admin: SimulatedBackend so the app stays fully usable in demo/dev.
UI never calls netsh directly — only through this service.

Fix #1 (err_log.txt, 29x repeat):
  netsh on RU Windows outputs cp866, subprocess(text=True) decoded as cp1251
  -> UnicodeDecodeError -> stdout=None -> None.upper() -> warning spam every tick.
  All subprocess calls now go through utils.win32.run_win_command (bytes +
  manual cp866/utf-8/cp1251 decode, never None, never raises).
  get_state() is cached for 2s (was 5 subprocess calls per 3s tick).
  Lock -> RLock: set_profile() calls get_state() while holding the lock.
"""
from __future__ import annotations
import threading, time
from dataclasses import dataclass
from app.config import Config
from utils.security import is_admin, is_windows
from utils.logging_utils import get_logger
from utils.win32 import run_win_command, safe_upper
log = get_logger("firewall")

@dataclass
class FirewallState:
    public: bool = True
    private: bool = True
    domain: bool = True
    emergency_shield: bool = False
    active_profile: str = "PRIVATE"
    network_name: str = "Unknown network"
    admin: bool = False

class _NetshBackend:
    def get_state(self, profile: str) -> bool:
        _, out = run_win_command(["netsh", "advfirewall", "show", f"{profile.lower()}profile", "state"], timeout=8)
        # netsh output: "State  ON" / "State  OFF". "ON" in upper() is safe here
        # because "OFF" does not contain "ON".
        return "ON" in safe_upper(out)
    def set_state(self, profile: str, on: bool) -> bool:
        rc, _ = run_win_command(["netsh", "advfirewall", "set", f"{profile.lower()}profile",
                                 "state", "on" if on else "off"], timeout=10)
        return rc == 0
    def block_all_inbound(self, on: bool) -> bool:
        try:
            for prof in ("public", "private", "domain"):
                run_win_command(["netsh", "advfirewall", "set", f"{prof}profile", "firewallpolicy",
                                 "blockinboundalways,allowoutbound" if on else "blockinbound,allowoutbound"], timeout=8)
            return True
        except Exception:
            return False

class _SimulatedBackend:
    def __init__(self): self._s = {"PUBLIC": True, "PRIVATE": True, "DOMAIN": True}
    def get_state(self, profile): return self._s.get(profile.upper(), True)
    def set_state(self, profile, on): self._s[profile.upper()] = bool(on); return True
    def block_all_inbound(self, on): return True

class FirewallService:
    _CACHE_TTL = 2.0  # seconds — get_state() is called every UI tick
    def __init__(self, config: Config | None = None, backend=None, on_change=None):
        self.config = config or Config()
        self._lock = threading.RLock()  # set_profile/set_emergency call get_state() while holding it
        self.on_change = on_change
        if backend is not None:
            self.backend = backend
        elif is_windows():
            self.backend = _NetshBackend()
        else:
            self.backend = _SimulatedBackend()
        self._emergency = bool(self.config.get("emergency_shield", False))
        if isinstance(self.backend, _SimulatedBackend):
            self.backend._s["PUBLIC"] = bool(self.config.get("firewall_public", True))
            self.backend._s["PRIVATE"] = bool(self.config.get("firewall_private", True))
        self._state_cache = None
        self._state_cache_ts = 0.0
    def _invalidate_cache(self):
        self._state_cache_ts = 0.0
    def get_state(self) -> FirewallState:
        with self._lock:
            now = time.time()
            if self._state_cache is not None and now - self._state_cache_ts < self._CACHE_TTL:
                return self._state_cache
            st = FirewallState(
                public=self.backend.get_state("PUBLIC"),
                private=self.backend.get_state("PRIVATE"),
                domain=self.backend.get_state("DOMAIN"),
                emergency_shield=self._emergency,
                active_profile=self._detect_profile(),
                network_name=self._detect_network_name(),
                admin=is_admin(),
            )
            self._state_cache = st; self._state_cache_ts = now
            return st
    def _detect_profile(self) -> str:
        if not is_windows():
            return "PRIVATE"
        _, out = run_win_command(["powershell", "-NoProfile", "-Command",
            "Get-NetConnectionProfile | Select-Object -First 1 -ExpandProperty NetworkCategory"], timeout=6)
        v = safe_upper(out.strip())
        return v if v in ("PUBLIC", "PRIVATE", "DOMAINAUTHENTICATED") else "PRIVATE"
    def _detect_network_name(self) -> str:
        if not is_windows():
            return "Local network (demo)"
        _, out = run_win_command(["powershell", "-NoProfile", "-Command",
            "Get-NetConnectionProfile | Select-Object -First 1 -ExpandProperty Name"], timeout=6)
        return out.strip() or "Unknown network"
    def set_profile(self, profile: str, on: bool, *, force=False) -> tuple[bool, str]:
        profile = profile.upper()
        if profile not in ("PUBLIC", "PRIVATE"):
            return False, "Unknown profile."
        with self._lock:
            ok = self.backend.set_state(profile, on)
            if ok:
                self.config.set(f"firewall_{profile.lower()}", bool(on))
                self._invalidate_cache()
                st = self.get_state()
                if self.on_change: self.on_change(st)
                return True, f"{profile.title()} firewall {'enabled' if on else 'disabled'}."
            return False, "Failed to apply. Run as administrator."
    def set_emergency_shield(self, on: bool) -> tuple[bool, str]:
        with self._lock:
            ok = self.backend.block_all_inbound(on)
            if ok:
                self._emergency = bool(on); self.config.set("emergency_shield", bool(on))
                self._invalidate_cache()
                if self.on_change: self.on_change(self.get_state())
                return True, "Emergency Shield " + ("ON — all unsolicited inbound blocked." if on else "OFF.")
            return False, "Failed to apply Emergency Shield."
    def restore_all(self):
        self.set_profile("PUBLIC", True); self.set_profile("PRIVATE", True); self.set_emergency_shield(False)
