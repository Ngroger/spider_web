"""Ports page — listening + established, suspicious highlighting."""
from __future__ import annotations
try:
    from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit
    _HAS=True
except Exception: _HAS=False
if _HAS:
    from ui.widgets.connection_table import ConnectionTable
    from core.port_inspector import PortInspector
    from utils.network_utils import port_service
    class PortsPage(QWidget):
        def __init__(self, app, parent=None):
            super().__init__(parent); self.app=app; self._conns=[]
            lay=QVBoxLayout(self); lay.setContentsMargins(20,18,20,18); lay.setSpacing(12)
            t=QLabel("Ports"); t.setObjectName("H1"); lay.addWidget(t)
            lay.addWidget(QLabel("Every listening port is a door into your PC. Sensitive ports are marked in the Risk column."))
            row=QHBoxLayout()
            self.search=QLineEdit(); self.search.setPlaceholderText("Filter by port, process, IP…"); self.search.textChanged.connect(self._apply); row.addWidget(self.search, 3)
            b=QPushButton("Refresh"); b.clicked.connect(self.refresh); row.addWidget(b); lay.addLayout(row)
            self.table=ConnectionTable(); lay.addWidget(self.table, 1)
            self.summary=QLabel(""); self.summary.setObjectName("Muted"); lay.addWidget(self.summary)
        def refresh(self, snapshot=None):
            self._conns = snapshot.get("connections", []) if snapshot else PortInspector().get_connections()
            self._apply()
        def _apply(self):
            listening=[c for c in self._conns if c.status=="LISTEN"]
            filtered=PortInspector.filter_connections(listening, query=self.search.text())
            self.table.set_connections(filtered, risk_fn=PortInspector.is_suspicious)
            services=", ".join(f"{c.local_port} ({port_service(c.local_port)})" for c in filtered[:10])
            self.summary.setText(f"{len(filtered)} listening ports.  Services: {services}" if services else f"{len(filtered)} listening ports.")
else:
    class PortsPage: pass
