"""Dataclass models — spec §11."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import uuid
from utils.formatting import now_iso

@dataclass
class ProcessInfo:
    pid: int | None = None
    name: str = "Unknown"
    exe: str = ""
    ppid: int | None = None
    parent_name: str = ""
    cmdline: str = ""
    username: str = ""
    def to_dict(self): return asdict(self)
    @classmethod
    def from_dict(cls, d: dict): return cls(**{k: d.get(k) for k in ("pid","name","exe","ppid","parent_name","cmdline","username") if k in d})

@dataclass
class NetworkConnection:
    proto: str = "TCP"
    local_ip: str = ""
    local_port: int | None = None
    remote_ip: str = ""
    remote_port: int | None = None
    status: str = ""
    pid: int | None = None
    process_name: str = ""
    exe: str = ""
    process_create_time: float | None = None  # psutil create_time — for "fresh only" filter (fix #4)
    def key(self): return (self.proto, self.local_ip, self.local_port, self.remote_ip, self.remote_port, self.pid)
    def to_dict(self): return asdict(self)

@dataclass
class FirewallRule:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    origin_application_path: str | None = None
    related_process_paths: list = field(default_factory=list)
    direction: str = "OUTBOUND"
    action: str = "BLOCK"
    protocol: str = "ANY"
    local_port: str | None = None
    remote_port: str | None = None
    remote_ip: str | None = None
    profile: str = "BOTH"
    priority: int = 100
    enabled: bool = True
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    def to_dict(self):
        d=asdict(self); return d

@dataclass
class NotificationGroup:
    group_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    origin_application: str = "Unknown"
    origin_pid: int | None = None
    related_processes: list = field(default_factory=list)  # list[ProcessInfo dict]
    connections: list = field(default_factory=list)        # list[NetworkConnection dict]
    direction: str = "OUTBOUND"
    risk_level: str = "LOW"
    status: str = "PENDING"
    created_at: str = field(default_factory=now_iso)
    expires_at: str | None = None
    @property
    def process_count(self): return max(1, len(self.related_processes))
    @property
    def connection_count(self): return len(self.connections)
    @property
    def destination(self) -> str:
        if not self.connections: return "—"
        c=self.connections[0]
        ip=c.get("remote_ip") if isinstance(c,dict) else getattr(c,"remote_ip","")
        port=c.get("remote_port") if isinstance(c,dict) else getattr(c,"remote_port","")
        return f"{ip}:{port}" if ip else "—"

@dataclass
class SecurityEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=now_iso)
    event_type: str = ""
    severity: str = "LOW"
    application_name: str | None = None
    pid: int | None = None
    remote_ip: str | None = None
    remote_port: int | None = None
    protocol: str | None = None
    decision: str | None = None
    details: str = ""
