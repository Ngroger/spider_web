"""Settings — sensitivity, refresh, theme note, data location, about."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QSpinBox, QCheckBox, QMessageBox
    _HAS=True
except Exception: _HAS=False
if _HAS:
    from app.config import app_data_dir
    class SettingsPage(QWidget):
        def __init__(self, app, parent=None):
            super().__init__(parent); self.app=app
            lay=QVBoxLayout(self); lay.setContentsMargins(20,18,20,18); lay.setSpacing(14)
            t=QLabel("Settings"); t.setObjectName("H1"); lay.addWidget(t)
            row=QHBoxLayout(); row.addWidget(QLabel("Notification sensitivity")); self.sens=QComboBox(); self.sens.addItems(["Minimal","Balanced","Strict"]); self.sens.setCurrentText(str(app.config.get("sensitivity","Balanced"))); row.addWidget(self.sens); row.addStretch(); lay.addLayout(row)
            row=QHBoxLayout(); row.addWidget(QLabel("Auto-refresh (seconds)")); self.refresh_sec=QSpinBox(); self.refresh_sec.setRange(1,30); self.refresh_sec.setValue(int(app.config.get("auto_refresh_sec",3))); row.addWidget(self.refresh_sec); row.addStretch(); lay.addLayout(row)
            self.notify_low=QCheckBox("Notify on low-risk events"); self.notify_low.setChecked(bool(app.config.get("notify_low_risk", False))); lay.addWidget(self.notify_low)
            self.sound=QCheckBox("Sound for high-risk alerts"); self.sound.setChecked(bool(app.config.get("sound", False))); lay.addWidget(self.sound)
            save=QPushButton("Save settings"); save.setObjectName("Primary"); save.clicked.connect(self._save); lay.addWidget(save)
            lay.addWidget(QLabel(f"Data location: {app_data_dir()}\nDatabase: spider_web.db  •  Config: config.json  •  Nothing leaves this PC."))
            lay.addWidget(QLabel("Spider Web Firewall v2.0 — Windows 10/11, Python + PySide6, netsh, SQLite.\nDesign: black (#0A0A0B) + muted red (#C50000), Bento grid, no emoji.\nSystem apps are hidden by default (Connections / Applications / Rules) — see Rules page, System filter."))
            lay.addStretch()
        def _save(self):
            self.app.config.set("sensitivity", self.sens.currentText()); self.app.notifications.set_sensitivity(self.sens.currentText())
            self.app.config.set("auto_refresh_sec", self.refresh_sec.value()); self.app.monitor.interval=self.refresh_sec.value()
            self.app.config.set("notify_low_risk", self.notify_low.isChecked()); self.app.config.set("sound", self.sound.isChecked())
            QMessageBox.information(self,"Saved","Settings saved.")
else:
    class SettingsPage: pass
