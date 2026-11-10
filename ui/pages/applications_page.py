"""Applications — network Task Manager (FR-29..36). Group by app, block/allow, terminate with confirm."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QMessageBox, QHeaderView
    from PySide6.QtCore import Qt
    import psutil
    _HAS=True
except Exception: _HAS=False
if _HAS:
    from core.process_grouping import group_connections_by_app
    from core.port_inspector import PortInspector
    from core.rules_engine import RulesEngine
    class ApplicationsPage(QWidget):
        def __init__(self, app, parent=None):
            super().__init__(parent); self.app=app; self._groups=[]
            lay=QVBoxLayout(self); lay.setContentsMargins(20,18,20,18); lay.setSpacing(12)
            t=QLabel("Applications"); t.setObjectName("H1"); lay.addWidget(t)
            lay.addWidget(QLabel("Which apps are using the network right now — grouped by originating application, helpers included."))
            from PySide6.QtWidgets import QCheckBox as _CB
            self.hide_system=_CB("Hide system apps"); self.hide_system.setChecked(True); self.hide_system.toggled.connect(lambda: self.refresh()); lay.addWidget(self.hide_system)
            self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Application","PID","Connections","Remote endpoints","Status"])
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.table.verticalHeader().setVisible(False); lay.addWidget(self.table, 1)
            btns=QHBoxLayout()
            for label, fn, obj in (("Block app", self._block, "Danger"),("Allow app", self._allow, None),("End process", self._kill, "Danger"),("Refresh", self.refresh, None)):
                b=QPushButton(label)
                if obj: b.setObjectName(obj)
                b.clicked.connect(fn); btns.addWidget(b)
            btns.addStretch(); lay.addLayout(btns)
            self.detail=QLabel("Select an app to see its connections."); self.detail.setWordWrap(True); self.detail.setObjectName("Mono"); lay.addWidget(self.detail)
            self.table.itemSelectionChanged.connect(self._show)
        def refresh(self, snapshot=None):
            conns = snapshot.get("connections", []) if snapshot else PortInspector().get_connections()
            if self.hide_system.isChecked():
                from notifications.notification_manager import is_system_exe
                conns=[c for c in conns if not is_system_exe(c.process_name, c.exe)]
            self._groups=group_connections_by_app(conns)
            self.table.setRowCount(0)
            blocked={ (r.origin_application_path or "").lower() for r in self.app.rules.list() if r.action=="BLOCK" and r.enabled }
            for g in self._groups:
                r=self.table.rowCount(); self.table.insertRow(r)
                endpoints=", ".join(sorted({f"{c.remote_ip}:{c.remote_port}" for c in g["connections"] if c.remote_ip})[:3])
                status="BLOCKED" if (g["exe"] or "").lower() in blocked else "Allowed"
                for col, v in enumerate([g["display_name"], str(g["pid"] or "—"), str(len(g["connections"])), endpoints or "—", status]):
                    self.table.setItem(r, col, QTableWidgetItem(v))
        def _sel(self):
            rows=self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
            return self._groups[rows[0].row()] if rows else None
        def _block(self):
            g=self._sel()
            if not g: return
            if QMessageBox.question(self,"Block application?", f"Block {g['display_name']} and its related processes?")!=QMessageBox.StandardButton.Yes: return
            rule=RulesEngine.rule_for_app_block(g["display_name"], g["exe"])
            self.app.rules.create(rule); self.app.logger.rule_change("CREATE", rule.name)
            QMessageBox.information(self,"Blocked", f"{g['display_name']} blocked."); self.refresh()
        def _allow(self):
            g=self._sel()
            if not g: return
            rule=RulesEngine.rule_for_app_allow(g["display_name"], g["exe"])
            self.app.rules.create(rule); self.app.logger.rule_change("CREATE", rule.name)
            QMessageBox.information(self,"Allowed", f"{g['display_name']} allowed."); self.refresh()
        def _kill(self):
            g=self._sel()
            if not g or not g["pid"]: return
            if QMessageBox.question(self,"End process?", f"Terminate {g['display_name']} (PID {g['pid']})? Unsaved work in that app will be lost.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes: return
            try:
                psutil.Process(g["pid"]).terminate(); self.app.logger.log("PROCESS_TERMINATED","MEDIUM", application_name=g["display_name"], pid=g["pid"], details="User terminated process from Applications page.")
            except Exception as e:
                QMessageBox.warning(self,"Failed", f"Could not terminate: {e}")
            self.refresh()
        def _show(self):
            g=self._sel()
            if not g: return
            lines=[f"{c.proto} {c.local_ip}:{c.local_port} → {c.remote_ip}:{c.remote_port} [{c.status}]" for c in g["connections"][:12]]
            self.detail.setText(f"{g['display_name']}, PID {g['pid']}, {g['exe'] or '—'}\n" + "\n".join(lines))
else:
    class ApplicationsPage: pass
