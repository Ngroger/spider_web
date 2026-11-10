"""Rules engine — spec §5.5, FR-37..42."""
from __future__ import annotations
from storage.models import FirewallRule
from app.constants import SYSTEM_APPS
from utils.validators import validate_rule_dict, ip_matches, port_in_range

PRESETS = [
    {"name":"Block app — all outbound","direction":"OUTBOUND","action":"BLOCK","protocol":"ANY","profile":"BOTH","priority":10},
    {"name":"Allow app — HTTPS only","direction":"OUTBOUND","action":"ALLOW","protocol":"TCP","remote_port":"443","profile":"BOTH","priority":20},
    {"name":"Block RDP inbound (3389)","direction":"INBOUND","action":"BLOCK","protocol":"TCP","local_port":"3389","profile":"PUBLIC","priority":10},
    {"name":"Block Telnet (23)","direction":"BOTH","action":"BLOCK","protocol":"TCP","local_port":"23","remote_port":"23","profile":"BOTH","priority":10},
    {"name":"Block suspicious IP","direction":"BOTH","action":"BLOCK","protocol":"ANY","profile":"BOTH","priority":5},
    {"name":"Allow LAN only","direction":"BOTH","action":"ALLOW","protocol":"ANY","remote_ip":"192.168.0.0/16","profile":"PRIVATE","priority":30},
]

def is_system_exe(exe_name: str | None, exe_path: str | None = None) -> bool:
    """Same definition as notifications — single source is constants.SYSTEM_EXES."""
    from notifications.notification_manager import is_system_exe as _ise
    return _ise(exe_name, exe_path)

def system_filter_rules() -> list[FirewallRule]:
    """Fix #5: one ALLOW + silent rule per system app, priority 1 (first).
    Created from Rules page -> "Add system rules". System traffic is then
    allowed by an explicit rule and never reaches notification logic."""
    out = []
    for exe, label in SYSTEM_APPS:
        out.append(FirewallRule(
            name=f"System: {label} — allow, no notifications",
            origin_application_path=None, direction="BOTH", action="ALLOW",
            protocol="ANY", profile="BOTH", priority=1))
    return out

class RulesEngine:
    def __init__(self, repo=None): self.repo=repo
    @staticmethod
    def validate(rule_dict: dict) -> list[str]:
        return validate_rule_dict(rule_dict)
    @staticmethod
    def find_conflicts(rules: list[FirewallRule], new: FirewallRule) -> list[FirewallRule]:
        """Conflict = same direction/profile/protocol overlapping ports/IP/app but opposite action."""
        out=[]
        for r in rules:
            if r.id==new.id or not r.enabled: continue
            if r.direction not in ("BOTH", new.direction) and new.direction!="BOTH": continue
            if r.profile not in ("BOTH", new.profile) and new.profile!="BOTH": continue
            if r.protocol not in ("ANY", new.protocol) and new.protocol!="ANY": continue
            if r.action==new.action: continue
            # overlap on app OR on ports/IP — conservative: flag if any dimension overlaps
            app_overlap = (not r.origin_application_path or not new.origin_application_path or
                           r.origin_application_path.lower()==(new.origin_application_path or "").lower())
            port_overlap = True
            if r.local_port and new.local_port and r.local_port!=new.local_port: port_overlap=False
            if r.remote_port and new.remote_port and r.remote_port!=new.remote_port: port_overlap=False
            if app_overlap and port_overlap:
                out.append(r)
        return out
    @staticmethod
    def evaluate(rules: list[FirewallRule], *, direction, protocol, local_port=None, remote_port=None,
                 remote_ip=None, app_path=None) -> str:
        """First matching rule by priority wins. Returns ALLOW / BLOCK / ASK / ALLOW (default)."""
        enabled=[r for r in rules if r.enabled]
        for r in sorted(enabled, key=lambda x: (x.priority, x.created_at)):
            if r.direction not in ("BOTH", direction): continue
            if r.protocol not in ("ANY", protocol): continue
            if local_port is not None and not port_in_range(local_port, r.local_port): continue
            if remote_port is not None and not port_in_range(remote_port, r.remote_port): continue
            if remote_ip and not ip_matches(remote_ip, r.remote_ip): continue
            if app_path and r.origin_application_path and r.origin_application_path.lower()!=app_path.lower(): continue
            return r.action
        return "ALLOW"
    @staticmethod
    def rule_for_app_block(app_name: str, exe: str | None = None, related: list | None = None) -> FirewallRule:
        return FirewallRule(
            name=f"Block {app_name}", origin_application_path=exe or None,
            related_process_paths=list(related or []), direction="BOTH", action="BLOCK",
            protocol="ANY", profile="BOTH", priority=10)
    @staticmethod
    def rule_for_app_allow(app_name: str, exe: str | None = None) -> FirewallRule:
        return FirewallRule(
            name=f"Allow {app_name}", origin_application_path=exe or None,
            direction="BOTH", action="ALLOW", protocol="ANY", profile="BOTH", priority=20)
    @staticmethod
    def rule_for_ip_block(ip: str, temporary=False) -> FirewallRule:
        return FirewallRule(
            name=f"Block IP {ip}" + (" (temporary)" if temporary else ""),
            direction="BOTH", action="BLOCK", protocol="ANY", remote_ip=ip, profile="BOTH", priority=5)
