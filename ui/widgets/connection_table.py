"""Reusable connection table — mono font for IP/port/PID, sortable."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    _HAS=True
except Exception: _HAS=False
HEADERS=["Process","PID","Proto","Local","Remote","State","Risk"]
if _HAS:
    class ConnectionTable(QTableWidget):
        def __init__(self, parent=None):
            super().__init__(0, len(HEADERS), parent)
            self.setHorizontalHeaderLabels(HEADERS)
            self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            self.setSortingEnabled(True); self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.verticalHeader().setVisible(False)
            self.mono=QFont("JetBrains Mono", 10)
        def set_connections(self, conns, risk_fn=None):
            self.setSortingEnabled(False); self.setRowCount(0)
            for c in conns:
                r=self.rowCount(); self.insertRow(r)
                vals=[c.process_name or "—", str(c.pid or "—"), c.proto,
                      f"{c.local_ip}:{c.local_port}", f"{c.remote_ip}:{c.remote_port}" if c.remote_ip else "—",
                      c.status or "—", ""]
                if risk_fn:
                    ok, why = risk_fn(c); vals[-1] = ("Suspicious: " + why) if ok else "OK"
                for col, v in enumerate(vals):
                    it=QTableWidgetItem(v)
                    if col in (1,3,4): it.setFont(self.mono)
                    if col == 0: it.setData(Qt.ItemDataRole.UserRole, c)  # fix: selection survives sorting
                    self.setItem(r, col, it)
            self.setSortingEnabled(True)
        def selected_connection_index(self):
            rows=self.selectionModel().selectedRows() if self.selectionModel() else []
            return rows[0].row() if rows else -1
else:
    class ConnectionTable: pass
