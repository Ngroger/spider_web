"""Event logger — thin wrapper over EventRepository, spec §5.6 FR-43."""
from __future__ import annotations
from storage.models import SecurityEvent
from storage.event_repository import EventRepository
from utils.formatting import now_iso

class EventLogger:
    def __init__(self, repo: EventRepository): self.repo=repo
    def log(self, event_type, severity="LOW", application_name=None, pid=None, remote_ip=None,
            remote_port=None, protocol=None, decision=None, details="") -> SecurityEvent:
        ev=SecurityEvent(timestamp=now_iso(), event_type=event_type, severity=severity,
                         application_name=application_name, pid=pid, remote_ip=remote_ip,
                         remote_port=remote_port, protocol=protocol, decision=decision, details=details)
        return self.repo.add(ev)
    # convenience
    def firewall_change(self, profile, old, new):
        return self.log("FIREWALL_CHANGE", "MEDIUM", decision=f"{profile} {old}→{new}",
                        details=f"Firewall {profile} changed from {old} to {new}.")
    def rule_change(self, action, rule_name, old=None, new=None):
        return self.log("RULE_CHANGE", "LOW", decision=action, details=f"{action}: {rule_name} (old={old} new={new})")
    def connection_decision(self, app, decision, remote_ip=None, remote_port=None, protocol=None, details=""):
        return self.log("CONNECTION", "MEDIUM" if decision=="BLOCKED" else "LOW", application_name=app,
                        remote_ip=remote_ip, remote_port=remote_port, protocol=protocol, decision=decision, details=details)
