"""Threat detection — spec §5.6, FR-44/45. Threshold + cooldown, explainable."""
from __future__ import annotations
import time
from collections import defaultdict, deque
from app.constants import PORT_SCAN_MIN_PORTS, PORT_SCAN_WINDOW_SEC, BRUTE_FORCE_MIN_ATTEMPTS, BRUTE_FORCE_WINDOW_SEC
from utils.network_utils import is_external_ip, is_suspicious_port

class ThreatDetector:
    def __init__(self, port_scan_min=PORT_SCAN_MIN_PORTS, brute_min=BRUTE_FORCE_MIN_ATTEMPTS):
        # NOTE (fix #4, corrected): observe() MUST be called once per NEW
        # connection, not once per poll. That filtering lives in
        # MainWindow._tick (only new (pid, ip, port) keys are fed here).
        # An earlier attempt at a 2-second dedup INSIDE observe() was REMOVED:
        # repeated attempts to the SAME port within 2s are exactly what a
        # brute-force looks like — deduping them broke brute-force detection
        # and its tests. Do NOT re-add a time-based dedup here.
        self.port_scan_min=port_scan_min; self.brute_min=brute_min
        self._port_attempts: dict[str, deque] = defaultdict(deque)   # ip -> (ts, port)
        self._inbound_attempts: dict[str, deque] = defaultdict(deque) # ip -> ts
        self._last_alert: dict[str, float] = {}
        self.cooldown_sec = 300
    def _prune(self, dq, window):
        now=time.time()
        while dq and now-dq[0][0] > window if isinstance(dq[0], tuple) else now-dq[0] > window:
            dq.popleft()
    def observe(self, *, remote_ip, local_port=None, remote_port=None, direction="INBOUND", process_name=""):
        """Feed one connection attempt. Returns list of alert dicts (may be empty)."""
        if not remote_ip or not is_external_ip(remote_ip):
            return []
        now=time.time(); alerts=[]
        if direction=="INBOUND":
            dq=self._inbound_attempts[remote_ip]; dq.append(now)
            while dq and now-dq[0] > BRUTE_FORCE_WINDOW_SEC: dq.popleft()
            if len(dq) >= self.brute_min and self._cooldown_ok(f"brute:{remote_ip}", now):
                self._last_alert[f"brute:{remote_ip}"]=now
                alerts.append({"type":"BRUTE_FORCE","severity":"HIGH","remote_ip":remote_ip,
                               "details":f"{len(dq)} inbound attempts from {remote_ip} in {BRUTE_FORCE_WINDOW_SEC}s — possible brute-force."})
            if local_port is not None:
                pq=self._port_attempts[remote_ip]; pq.append((now, local_port))
                while pq and now-pq[0][0] > PORT_SCAN_WINDOW_SEC: pq.popleft()
                distinct={p for _,p in pq}
                if len(distinct) >= self.port_scan_min and self._cooldown_ok(f"scan:{remote_ip}", now):
                    self._last_alert[f"scan:{remote_ip}"]=now
                    ports=sorted(distinct)
                    alerts.append({"type":"PORT_SCAN","severity":"HIGH","remote_ip":remote_ip,
                                   "details":f"{remote_ip} probed {len(distinct)} ports ({', '.join(map(str,ports[:10]))}) — possible port scan."})
        if is_suspicious_port(local_port) or is_suspicious_port(remote_port):
            if self._cooldown_ok(f"susp:{remote_ip}:{local_port}:{remote_port}", now):
                self._last_alert[f"susp:{remote_ip}:{local_port}:{remote_port}"]=now
                alerts.append({"type":"SUSPICIOUS_PORT","severity":"MEDIUM","remote_ip":remote_ip,
                               "details":f"Suspicious port in connection: local {local_port}, remote {remote_port} ({process_name or 'unknown'})."})
        return alerts
    def _cooldown_ok(self, key, now):
        return now - self._last_alert.get(key, 0) >= self.cooldown_sec
    def health_score(self, *, firewall_public, firewall_private, emergency_shield,
                     listening_count, suspicious_listening, unknown_apps, recent_high_alerts) -> tuple[int, list[str]]:
        """0..100, explainable. Spec FR-47."""
        score=100; reasons=[]
        if not firewall_public: score-=30; reasons.append("Public firewall is OFF (−30)")
        if not firewall_private: score-=15; reasons.append("Private firewall is OFF (−15)")
        if emergency_shield: score=min(100, score+5); reasons.append("Emergency Shield is ON (+5)")
        if suspicious_listening: score-=min(20, 5*suspicious_listening); reasons.append(f"{suspicious_listening} sensitive listening port(s) (−{min(20,5*suspicious_listening)})")
        if listening_count>25: score-=5; reasons.append(f"{listening_count} listening ports (−5)")
        if unknown_apps: score-=min(15, 3*unknown_apps); reasons.append(f"{unknown_apps} unknown app(s) with network access (−{min(15,3*unknown_apps)})")
        if recent_high_alerts: score-=min(20, 5*recent_high_alerts); reasons.append(f"{recent_high_alerts} high-severity alert(s) recently (−{min(20,5*recent_high_alerts)})")
        return max(0, min(100, score)), reasons
