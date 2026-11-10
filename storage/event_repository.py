"""Security event log repository."""
from __future__ import annotations
from storage.models import SecurityEvent
from storage.database import Database

class EventRepository:
    def __init__(self, db: Database): self.db=db
    def add(self, ev: SecurityEvent) -> SecurityEvent:
        self.db.execute("""INSERT INTO security_events
          (id,timestamp,event_type,severity,application_name,pid,remote_ip,remote_port,protocol,decision,details)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
          (ev.id, ev.timestamp, ev.event_type, ev.severity, ev.application_name, ev.pid,
           ev.remote_ip, ev.remote_port, ev.protocol, ev.decision, ev.details))
        return ev
    def list(self, limit=500, severity=None, event_type=None, search=None) -> list[SecurityEvent]:
        sql="SELECT * FROM security_events WHERE 1=1"; params=[]
        if severity: sql+=" AND severity=?"; params.append(severity)
        if event_type: sql+=" AND event_type=?"; params.append(event_type)
        if search:
            sql+=" AND (application_name LIKE ? OR remote_ip LIKE ? OR details LIKE ?)"; params += [f"%{search}%"]*3
        sql+=" ORDER BY timestamp DESC LIMIT ?"; params.append(limit)
        out=[]
        for r in self.db.query(sql, tuple(params)):
            out.append(SecurityEvent(id=r["id"], timestamp=r["timestamp"], event_type=r["event_type"],
                severity=r["severity"], application_name=r["application_name"], pid=r["pid"],
                remote_ip=r["remote_ip"], remote_port=r["remote_port"], protocol=r["protocol"],
                decision=r["decision"], details=r["details"] or ""))
        return out
    def count(self) -> int:
        r=self.db.query("SELECT COUNT(*) c FROM security_events"); return r[0]["c"] if r else 0
    def clear_older_than(self, iso_cutoff: str):
        self.db.execute("DELETE FROM security_events WHERE timestamp < ?", (iso_cutoff,))
    def clear_all(self): self.db.execute("DELETE FROM security_events")
