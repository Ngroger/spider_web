"""Application controller — wires services, no UI logic here (spec §8/10)."""
from __future__ import annotations
import time
from pathlib import Path
from app.config import Config, default_db_path
from storage.database import Database
from storage.rule_repository import RuleRepository
from storage.event_repository import EventRepository
from storage.settings_repository import SettingsRepository
from core.firewall_service import FirewallService
from core.network_monitor import NetworkMonitor
from core.event_logger import EventLogger
from core.rules_engine import RulesEngine
from core.threat_detector import ThreatDetector
from notifications.notification_manager import NotificationManager

class Application:
    def __init__(self, db_path: Path | None = None, config: Config | None = None):
        # Fix #4: moment the firewall itself started. Anything already connected
        # at this moment is "old" and must never produce a notification.
        self.started_at: float = time.time()
        # (pid, remote_ip, remote_port, proto) that already existed at startup.
        # Filled in start_monitoring() from the first snapshot.
        self.baseline_conn_keys: set = set()
        self.config = config or Config()
        self.db = Database(db_path or default_db_path())
        self.rules = RuleRepository(self.db)
        self.events = EventRepository(self.db)
        self.settings = SettingsRepository(self.db)
        self.logger = EventLogger(self.events)
        self.firewall = FirewallService(self.config)
        self.monitor = NetworkMonitor(interval_sec=int(self.config.get("auto_refresh_sec", 3)))
        self.rules_engine = RulesEngine(self.rules)
        self.threats = ThreatDetector()
        self.notifications = NotificationManager(self.config,
            trusted_apps=list(self.config.get("trusted_apps", [])))
        self.notifications.set_sensitivity(str(self.config.get("sensitivity", "Balanced")))
        self.notifications.set_session_start(self.started_at)
        # seed demo rules on first run so Rules page is never empty
        if not self.rules.list():
            self._seed_demo_rules()
    def _seed_demo_rules(self):
        from storage.models import FirewallRule
        from utils.formatting import now_iso
        demo=[
            FirewallRule(name="Block Telnet (23) — preset", direction="BOTH", action="BLOCK", protocol="TCP",
                         local_port="23", remote_port="23", profile="BOTH", priority=10),
            FirewallRule(name="Block RDP inbound (3389) — preset", direction="INBOUND", action="BLOCK", protocol="TCP",
                         local_port="3389", profile="PUBLIC", priority=10),
            FirewallRule(name="Allow HTTPS outbound — preset", direction="OUTBOUND", action="ALLOW", protocol="TCP",
                         remote_port="443", profile="BOTH", priority=20),
        ]
        for r in demo:
            try: self.rules.create(r)
            except Exception: pass
    def start_monitoring(self):
        # Fix #4: capture baseline BEFORE the UI starts ticking, so old
        # connections are known to be old and are never notified about.
        try:
            snap = self.monitor.snapshot()
            self.baseline_conn_keys = {(c.pid, c.remote_ip, c.remote_port, c.proto)
                                       for c in snap.get("connections", [])}
            self.notifications.set_baseline(self.baseline_conn_keys)
        except Exception:
            pass
        self.monitor.start()
    def stop(self):
        try: self.monitor.stop()
        except Exception: pass
        try: self.db.close()
        except Exception: pass
    def incident_response(self) -> str:
        """One-click Incident Response (FR-49): Emergency Shield ON + log + return summary."""
        ok, msg = self.firewall.set_emergency_shield(True)
        self.logger.log("INCIDENT_RESPONSE", "HIGH", decision="EMERGENCY_SHIELD_ON",
                        details="Incident Response: Emergency Shield enabled, recent threats surfaced.")
        return msg
