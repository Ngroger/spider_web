"""Key-value settings backed by SQLite (mirrors Config JSON for UI)."""
from __future__ import annotations
import json
from storage.database import Database
class SettingsRepository:
    def __init__(self, db: Database): self.db=db
    def get(self, key, default=None):
        rows=self.db.query("SELECT value FROM app_settings WHERE key=?", (key,))
        if not rows: return default
        try: return json.loads(rows[0]["value"])
        except Exception: return rows[0]["value"]
    def set(self, key, value):
        self.db.execute("INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, json.dumps(value, ensure_ascii=False)))
    def all(self) -> dict:
        return {r["key"]: self.get(r["key"]) for r in self.db.query("SELECT key FROM app_settings")}
