"""SQLite storage — spec §12. WAL, local-only, no network."""
from __future__ import annotations
import sqlite3, json
from pathlib import Path
from app.config import default_db_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS firewall_rules (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, origin_application_path TEXT,
    related_process_paths TEXT, direction TEXT NOT NULL, action TEXT NOT NULL,
    protocol TEXT NOT NULL, local_port TEXT, remote_port TEXT, remote_ip TEXT,
    profile TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notification_groups (
    id TEXT PRIMARY KEY, origin_application TEXT NOT NULL, origin_pid INTEGER,
    related_processes TEXT, risk_level TEXT NOT NULL, status TEXT NOT NULL,
    created_at TEXT NOT NULL, expires_at TEXT, details TEXT
);
CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
    severity TEXT NOT NULL, application_name TEXT, pid INTEGER, remote_ip TEXT,
    remote_port INTEGER, protocol TEXT, decision TEXT, details TEXT
);
CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_rules_priority ON firewall_rules(priority);
"""

class Database:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
    @property
    def conn(self): return self._conn
    def execute(self, sql, params=()):
        cur = self._conn.execute(sql, params); self._conn.commit(); return cur
    def query(self, sql, params=()):
        return self._conn.execute(sql, params).fetchall()
    def close(self):
        try: self._conn.close()
        except Exception: pass
    # JSON helpers
    @staticmethod
    def dumps(v): return json.dumps(v or [], ensure_ascii=False)
    @staticmethod
    def loads(s):
        try: return json.loads(s) if s else []
        except Exception: return []
