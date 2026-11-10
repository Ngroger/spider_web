"""Logs — FR-43/48: filter, search, export CSV/JSON, clear."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QMessageBox
    _HAS=True
except Exception: _HAS=False
if _HAS:
    import csv, json
    from utils.formatting import fmt_datetime
    class LogsPage(QWidget):
        def __init__(self, app, parent=None):
            super().__init__(parent); self.app=app
            lay=QVBoxLayout(self); lay.setContentsMargins(20,18,20,18); lay.setSpacing(12)
            t=QLabel("Security Log"); t.setObjectName("H1"); lay.addWidget(t)
            row=QHBoxLayout()
            self.search=QLineEdit(); self.search.setPlaceholderText("Search app, IP, details…"); self.search.textChanged.connect(self.refresh); row.addWidget(self.search, 3)
            self.sev=QComboBox(); self.sev.addItems(["All severities","LOW","MEDIUM","HIGH"]); self.sev.currentTextChanged.connect(self.refresh); row.addWidget(self.sev)
            self.typ=QComboBox(); self.typ.addItems(["All types","CONNECTION","FIREWALL_CHANGE","RULE_CHANGE","PORT_SCAN","BRUTE_FORCE","INCIDENT_RESPONSE"]); self.typ.currentTextChanged.connect(self.refresh); row.addWidget(self.typ)
            row.addStretch(); lay.addLayout(row)
            self.table=QTableWidget(0,6); self.table.setHorizontalHeaderLabels(["Time","Type","Severity","App","Remote","Decision / Details"])
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            self.table.verticalHeader().setVisible(False); lay.addWidget(self.table, 1)
            btns=QHBoxLayout()
            for label, fn in (("Export CSV", lambda: self._export("csv")),("Export JSON", lambda: self._export("json")),("Refresh", self.refresh),("Clear log", self._clear)):
                b=QPushButton(label); b.clicked.connect(fn); btns.addWidget(b)
            btns.addStretch(); self.count=QLabel(""); self.count.setObjectName("Muted"); btns.addWidget(self.count); lay.addLayout(btns)
            self.refresh()
        def _events(self):
            sev=None if self.sev.currentText()=="All severities" else self.sev.currentText()
            typ=None if self.typ.currentText()=="All types" else self.typ.currentText()
            return self.app.events.list(limit=500, severity=sev, event_type=typ, search=self.search.text() or None)
        def refresh(self):
            evs=self._events(); self.table.setRowCount(0)
            for e in evs:
                r=self.table.rowCount(); self.table.insertRow(r)
                for col,v in enumerate([fmt_datetime(e.timestamp), e.event_type, e.severity, e.application_name or "—",
                                        f"{e.remote_ip or '—'}:{e.remote_port or ''}", f"{e.decision or ''}  {e.details}"[:120]]):
                    self.table.setItem(r, col, QTableWidgetItem(v))
            self.count.setText(f"{len(evs)} events")
        def _export(self, fmt):
            evs=self._events()
            path,_=QFileDialog.getSaveFileName(self, "Export log", f"spider_web_log.{fmt}", f"*.{fmt}")
            if not path: return
            if fmt=="csv":
                with open(path,"w",newline="",encoding="utf-8") as f:
                    w=csv.writer(f); w.writerow(["timestamp","event_type","severity","application","pid","remote_ip","remote_port","protocol","decision","details"])
                    for e in evs: w.writerow([e.timestamp,e.event_type,e.severity,e.application_name,e.pid,e.remote_ip,e.remote_port,e.protocol,e.decision,e.details])
            else:
                with open(path,"w",encoding="utf-8") as f:
                    json.dump([e.__dict__ for e in evs], f, indent=2, ensure_ascii=False)
            QMessageBox.information(self,"Exported", f"{len(evs)} events → {path}")
        def _clear(self):
            if QMessageBox.question(self,"Clear log?", "Delete all security events?")!=QMessageBox.StandardButton.Yes: return
            self.app.events.clear_all(); self.refresh()
else:
    class LogsPage: pass
