"""Notifications — history, sensitivity, trusted apps, undo last decision."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit, QMessageBox
    _HAS=True
except Exception: _HAS=False
if _HAS:
    class NotificationsPage(QWidget):
        def __init__(self, app, parent=None):
            super().__init__(parent); self.app=app
            lay=QVBoxLayout(self); lay.setContentsMargins(20,18,20,18); lay.setSpacing(12)
            t=QLabel("Notifications"); t.setObjectName("H1"); lay.addWidget(t)
            lay.addWidget(QLabel("One notification per application launch — never one per process. System apps (svchost, System, etc.) and traffic from before the firewall started never notify."))
            row=QHBoxLayout(); row.addWidget(QLabel("Sensitivity:"))
            self.sens=QComboBox(); self.sens.addItems(["Minimal","Balanced","Strict"]); self.sens.setCurrentText(str(self.app.config.get("sensitivity","Balanced")))
            self.sens.currentTextChanged.connect(self._sens); row.addWidget(self.sens)
            row.addWidget(QLabel("Trusted app (exe name):"))
            self.trusted_in=QLineEdit(); self.trusted_in.setPlaceholderText("e.g. chrome.exe"); row.addWidget(self.trusted_in)
            add=QPushButton("Add trusted"); add.clicked.connect(self._add_trusted); row.addWidget(add)
            row.addStretch(); lay.addLayout(row)
            self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Time","Application","Destination","Risk","Status"])
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            self.table.verticalHeader().setVisible(False); lay.addWidget(self.table, 1)
            btns=QHBoxLayout()
            undo=QPushButton("Undo last decision"); undo.clicked.connect(self._undo); btns.addWidget(undo)
            demo=QPushButton("Show demo notification"); demo.clicked.connect(self._demo); btns.addWidget(demo)
            btns.addStretch(); lay.addLayout(btns)
            self.refresh()
        def _sens(self, v):
            self.app.config.set("sensitivity", v); self.app.notifications.set_sensitivity(v)
        def _add_trusted(self):
            name=self.trusted_in.text().strip().lower()
            if not name: return
            lst=list(self.app.config.get("trusted_apps", []))
            if name not in lst: lst.append(name); self.app.config.set("trusted_apps", lst); self.app.notifications.trusted_apps.add(name)
            self.trusted_in.clear(); QMessageBox.information(self,"Trusted", f"{name} will no longer trigger low-risk alerts.")
        def refresh(self):
            from utils.formatting import fmt_time
            groups=self.app.notifications.history; self.table.setRowCount(0)
            for g in reversed(groups[-100:]):
                r=self.table.rowCount(); self.table.insertRow(r)
                for col,v in enumerate([fmt_time(g.created_at), g.origin_application, g.destination, g.risk_level, g.status]):
                    self.table.setItem(r, col, QTableWidgetItem(v))
        def _undo(self):
            decided=[g for g in self.app.notifications.history if g.status in ("ALLOWED","BLOCKED")]
            if not decided: QMessageBox.information(self,"Nothing to undo","No decided notifications yet."); return
            g=decided[-1]; g.status="PENDING"; self.refresh()
            QMessageBox.information(self,"Undone", f"Decision for {g.origin_application} reverted to PENDING. Create / delete the matching rule in Rules if needed.")
        def _demo(self):
            from notifications.notification_manager import NotificationManager
            mgr=self.app.notifications
            risk=mgr.assess_risk(app_name="DemoApp", exe_name="demo.exe", remote_ip="93.184.216.34", remote_port=443, is_unknown=True)
            g=mgr.create_group(origin_application="DemoApp", origin_pid=1234,
                related_processes=[{"pid":1234,"name":"demo.exe"},{"pid":1235,"name":"demo_helper.exe"}],
                connections=[{"remote_ip":"93.184.216.34","remote_port":443,"proto":"TCP"}],
                direction="OUTBOUND", risk=risk)
            mw=self.window()
            if hasattr(mw,"show_notification"): mw.show_notification(g)
            self.refresh()
else:
    class NotificationsPage: pass
