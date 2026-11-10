"""App configuration: paths, defaults, settings keys. Local-only, no cloud."""
from __future__ import annotations
import json, os
from pathlib import Path

def app_data_dir() -> Path:
    # %APPDATA% on Windows, ~/.spider_web_firewall elsewhere (dev / tests)
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path.home() / ".spider_web_firewall"
    d = base / "SpiderWebFirewall"
    d.mkdir(parents=True, exist_ok=True)
    return d

def default_db_path() -> Path:
    return app_data_dir() / "spider_web.db"

def default_config_path() -> Path:
    return app_data_dir() / "config.json"

DEFAULT_SETTINGS = {
    "sensitivity": "Balanced",          # Minimal | Balanced | Strict
    "notify_low_risk": False,
    "notify_medium_risk": True,
    "notify_high_risk": True,
    "auto_refresh_sec": 3,
    "emergency_shield": False,
    "firewall_public": True,
    "firewall_private": True,
    "trusted_apps": [],                # list of exe names / paths approved by user
    "theme": "dark",
    "sound": False,
    "start_minimized": False,
    "log_retention_days": 30,
}

class Config:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else default_config_path()
        self._data = dict(DEFAULT_SETTINGS)
        self.load()
    def load(self):
        try:
            if self.path.exists():
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._data.update(raw)
        except Exception:
            pass
        return self
    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")
    def get(self, key, default=None):
        return self._data.get(key, default)
    def set(self, key, value):
        self._data[key] = value
        self.save()
    def all(self) -> dict:
        return dict(self._data)
